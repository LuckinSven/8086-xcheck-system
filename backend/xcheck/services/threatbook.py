from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from typing import Any
from urllib.parse import quote, quote_plus
from zoneinfo import ZoneInfo

import httpx
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from xcheck.models import (
    DailyUsage,
    StepAttempt,
    StepStatus,
    Task,
    TaskIP,
    TaskStatus,
    TaskStep,
    ThreatbookBatch,
    ThreatbookResult,
    utcnow,
)

SECRET_KEYS = {"apikey", "api_key", "authorization", "token", "secret"}
THREATBOOK_CONFIG_BOUNDS = {
    "batch_size": (1, 100),
    "safe_ips_per_minute": (1, 1000),
    "daily_budget": (1, None),
    "max_retries": (0, 3),
}


def parse_threatbook_execution_config(snapshot: str) -> dict[str, int]:
    try:
        loaded = json.loads(snapshot)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("任务的微步执行配置无效") from exc
    if not isinstance(loaded, dict):
        raise ValueError("任务的微步执行配置无效")
    parsed = {}
    for field, (minimum, maximum) in THREATBOOK_CONFIG_BOUNDS.items():
        value = loaded.get(field)
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < minimum
            or (maximum is not None and value > maximum)
        ):
            raise ValueError("任务的微步执行配置无效")
        parsed[field] = value
    return parsed


def safe_integration_error(exc: Exception, secret: str = "") -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    if isinstance(exc, httpx.TimeoutException):
        return "请求超时"
    if isinstance(exc, httpx.RequestError):
        return "网络连接失败"
    message = str(exc)
    if secret:
        for candidate in {secret, quote(secret, safe=""), quote_plus(secret, safe="")}:
            message = message.replace(candidate, "***")
    return message[:500] or type(exc).__name__


def redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "***" if key.lower() in SECRET_KEYS else redact_secrets(item) for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value


def parse_ip_result(ip: str, payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("微步API返回的IP情报结构不正确")
    basic = payload.get("basic") or {}
    if not isinstance(basic, dict):
        raise ValueError("微步API返回的基础情报结构不正确")
    location = basic.get("location") or {}
    if not isinstance(location, dict):
        raise ValueError("微步API返回的地区结构不正确")
    asn = payload.get("asn") or {}
    if not isinstance(asn, dict):
        raise ValueError("微步API返回的ASN结构不正确")
    judgments = payload.get("judgments") or []
    if not isinstance(judgments, list) or any(not isinstance(item, str) for item in judgments):
        raise ValueError("微步API返回的威胁标签结构不正确")
    is_malicious = payload.get("is_malicious", False)
    if not isinstance(is_malicious, bool):
        raise ValueError("微步API返回的恶意结论结构不正确")
    asn_number = asn.get("number")
    if asn_number is not None and (not isinstance(asn_number, int) or isinstance(asn_number, bool)):
        raise ValueError("微步API返回的ASN编号结构不正确")
    return {
        "ip": ip,
        "is_malicious": is_malicious,
        "confidence_level": payload.get("confidence_level"),
        "severity": payload.get("severity"),
        "judgments": judgments,
        "country": location.get("country"),
        "province": location.get("province"),
        "city": location.get("city"),
        "carrier": basic.get("carrier"),
        "asn_number": asn_number,
        "asn_name": asn.get("info"),
        "scene": payload.get("scene"),
        "update_time": payload.get("update_time"),
        "permalink": payload.get("permalink"),
        "raw": redact_secrets(payload),
    }


class GlobalRateLimiter:
    def __init__(self, ips_per_minute: int, clock=time.monotonic, sleeper=time.sleep):
        self.interval_per_ip = 60.0 / ips_per_minute
        self.clock = clock
        self.sleeper = sleeper
        self._next_allowed = 0.0
        self._lock = threading.Lock()

    def reconfigure(self, ips_per_minute: int) -> None:
        with self._lock:
            self.interval_per_ip = 60.0 / ips_per_minute

    def acquire(self, ip_count: int) -> None:
        with self._lock:
            now = self.clock()
            wait_seconds = max(0.0, self._next_allowed - now)
            self._next_allowed = max(now, self._next_allowed) + self.interval_per_ip * ip_count
        if wait_seconds:
            self.sleeper(round(wait_seconds, 6))


class ThreatBookClient:
    def __init__(self, url: str, api_key: str, timeout: float = 45.0, transport=None):
        self.url = url
        self.api_key = api_key
        self.timeout = timeout
        self.transport = transport

    def query(self, addresses: list[str]) -> dict:
        with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
            response = client.get(
                self.url,
                params={"apikey": self.api_key, "resource": ",".join(addresses)},
            )
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, dict) or "response_code" not in payload:
            raise ValueError("微步API返回结构不正确")
        return payload


def _step(session: Session, task_id: str) -> TaskStep:
    return session.scalar(
        select(TaskStep).where(TaskStep.task_id == task_id, TaskStep.name == "threatbook_query")
    )


def _usage_date(settings):
    return datetime.now(ZoneInfo(settings.app_timezone)).date()


def run_threatbook(
    factory: sessionmaker[Session],
    task_id: str,
    client: ThreatBookClient,
    limiter: GlobalRateLimiter,
    settings,
) -> None:
    with factory() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise ValueError("任务不存在")
        if task.status not in {
            TaskStatus.QUEUED.value,
            TaskStatus.WAITING_THREATBOOK.value,
            TaskStatus.PAUSED_QUOTA.value,
        }:
            raise ValueError("任务尚未进入微步查询阶段")
        execution_config = parse_threatbook_execution_config(task.config_snapshot)
        batch_size = execution_config["batch_size"]
        daily_budget = execution_config["daily_budget"]
        max_retries = execution_config["max_retries"]
        limiter.reconfigure(execution_config["safe_ips_per_minute"])
        addresses = [
            item.normalized_ip
            for item in session.scalars(
                select(TaskIP)
                .where(TaskIP.task_id == task_id, TaskIP.stage == "threatbook_ready")
                .order_by(TaskIP.id)
            )
        ]
        task.status = TaskStatus.RUNNING.value
        task.current_step = "threatbook_query"
        task.error_summary = None
        task.failed_count = 0
        step = _step(session, task_id)
        step.status = StepStatus.RUNNING.value
        step.started_at = step.started_at or utcnow()
        step.finished_at = None
        step.error_summary = None
        original_total = (
            session.scalar(
                select(func.count())
                .select_from(TaskIP)
                .where(
                    TaskIP.task_id == task_id,
                    TaskIP.stage.in_(["threatbook_ready", "threatbook_complete"]),
                )
            )
            or 0
        )
        last_batch_number = (
            session.scalar(
                select(func.max(ThreatbookBatch.batch_number)).where(
                    ThreatbookBatch.task_id == task_id
                )
            )
            or 0
        )
        remaining_batch_count = (len(addresses) + batch_size - 1) // batch_size
        step.progress_total = max(
            step.progress_total,
            original_total,
            step.progress_current + len(addresses),
        )
        step.total_batches = max(step.total_batches, last_batch_number + remaining_batch_count)
        session.commit()

        for batch_number, offset in enumerate(
            range(0, len(addresses), batch_size), start=last_batch_number + 1
        ):
            batch_addresses = addresses[offset : offset + batch_size]
            usage = session.get(DailyUsage, _usage_date(settings))
            if usage is None:
                usage = DailyUsage(usage_date=_usage_date(settings), successful_ips=0)
                session.add(usage)
                session.flush()
            if usage.successful_ips + len(batch_addresses) > daily_budget:
                task.status = TaskStatus.PAUSED_QUOTA.value
                step.status = StepStatus.WAITING.value
                step.checkpoint = json.dumps({"next_batch": batch_number}, ensure_ascii=False)
                session.commit()
                return

            batch = ThreatbookBatch(
                task_id=task_id,
                batch_number=batch_number,
                status="running",
                addresses_json=json.dumps(batch_addresses),
                unresolved_json=json.dumps(batch_addresses),
            )
            session.add(batch)
            session.flush()
            last_error = None
            succeeded = False
            attempts_used = 0
            for attempt_number in range(1, max_retries + 2):
                attempts_used = attempt_number
                attempt = StepAttempt(
                    task_id=task_id,
                    step_name="threatbook_query",
                    batch_id=batch.id,
                    attempt_number=attempt_number,
                    status="running",
                    safe_request_json=json.dumps({"resource_count": len(batch_addresses)}),
                )
                session.add(attempt)
                session.commit()
                response_code = None
                try:
                    limiter.acquire(len(batch_addresses))
                    payload = client.query(batch_addresses)
                    response_code = int(payload.get("response_code", -999))
                    if response_code < 0:
                        raise RuntimeError(f"微步错误码 {response_code}")
                    data = payload.get("data")
                    if not isinstance(data, dict):
                        raise ValueError("微步API返回的数据结构不正确")

                    prepared = []
                    for ip in batch_addresses:
                        if ip not in data:
                            continue
                        ip_payload = data[ip]
                        if not isinstance(ip_payload, dict):
                            raise ValueError("微步API返回的IP情报结构不正确")
                        mapped = parse_ip_result(ip, ip_payload)
                        task_ip = session.scalar(
                            select(TaskIP).where(
                                TaskIP.task_id == task_id,
                                TaskIP.normalized_ip == ip,
                            )
                        )
                        if task_ip is None:
                            raise ValueError("微步结果无法关联任务IP")
                        prepared.append((task_ip, mapped))

                    resolved_ips = {mapped["ip"] for _task_ip, mapped in prepared}
                    for task_ip, mapped in prepared:
                        session.add(
                            ThreatbookResult(
                                task_ip_id=task_ip.id,
                                batch_id=batch.id,
                                is_malicious=mapped["is_malicious"],
                                confidence_level=mapped["confidence_level"],
                                severity=mapped["severity"],
                                judgments_json=json.dumps(mapped["judgments"], ensure_ascii=False),
                                country=mapped["country"],
                                province=mapped["province"],
                                city=mapped["city"],
                                carrier=mapped["carrier"],
                                asn_number=mapped["asn_number"],
                                asn_name=mapped["asn_name"],
                                scene=mapped["scene"],
                                update_time=mapped["update_time"],
                                permalink=mapped["permalink"],
                                raw_json=json.dumps(mapped["raw"], ensure_ascii=False),
                            )
                        )
                        task_ip.stage = "threatbook_complete"

                    attempt.status = "completed"
                    attempt.response_code = response_code
                    attempt.finished_at = utcnow()
                    batch.status = "completed"
                    batch.response_code = response_code
                    batch.response_message = "微步接口请求完成"
                    batch.unresolved_json = json.dumps(
                        [ip for ip in batch_addresses if ip not in resolved_ips]
                    )
                    batch.attempt_count = attempt_number
                    batch.finished_at = utcnow()
                    usage.successful_ips += len(prepared)
                    step.current_batch = batch_number
                    step.progress_current += len(prepared)
                    session.commit()
                    succeeded = True
                    break
                except Exception as exc:
                    session.rollback()
                    last_error = exc
                    attempt = session.get(StepAttempt, attempt.id)
                    batch = session.get(ThreatbookBatch, batch.id)
                    attempt.status = "failed"
                    attempt.response_code = response_code
                    attempt.error_type = type(exc).__name__
                    attempt.error_message = (
                        "结果保存失败"
                        if isinstance(exc, SQLAlchemyError)
                        else safe_integration_error(exc, client.api_key)
                    )
                    attempt.finished_at = utcnow()
                    batch.response_code = response_code
                    batch.response_message = "微步接口请求失败"
                    session.commit()
                    if attempt_number <= max_retries:
                        time.sleep((2, 5, 10)[attempt_number - 1])
            if not succeeded:
                task = session.get(Task, task_id)
                step = _step(session, task_id)
                batch = session.get(ThreatbookBatch, batch.id)
                batch.status = "failed"
                batch.attempt_count = attempts_used
                batch.finished_at = utcnow()
                task.status = (
                    TaskStatus.PARTIAL_SUCCESS.value
                    if step.progress_current > 0
                    else TaskStatus.FAILED.value
                )
                task.error_summary = (
                    "结果保存失败"
                    if isinstance(last_error, SQLAlchemyError)
                    else safe_integration_error(last_error, client.api_key)
                )
                task.failed_count = (
                    session.scalar(
                        select(func.count())
                        .select_from(TaskIP)
                        .where(TaskIP.task_id == task_id, TaskIP.stage == "threatbook_ready")
                    )
                    or 0
                )
                step.status = StepStatus.FAILED.value
                step.error_summary = task.error_summary
                step.current_batch = batch_number
                step.output_count = step.progress_current
                step.finished_at = utcnow()
                session.commit()
                return

        task = session.get(Task, task_id)
        step = _step(session, task_id)
        task.malicious_count = (
            session.scalar(
                select(func.count())
                .select_from(ThreatbookResult)
                .join(TaskIP)
                .where(TaskIP.task_id == task_id, ThreatbookResult.is_malicious.is_(True))
            )
            or 0
        )
        task.high_confidence_count = (
            session.scalar(
                select(func.count())
                .select_from(ThreatbookResult)
                .join(TaskIP)
                .where(
                    TaskIP.task_id == task_id,
                    ThreatbookResult.is_malicious.is_(True),
                    ThreatbookResult.confidence_level == "high",
                )
            )
            or 0
        )
        unresolved = (
            session.scalar(
                select(func.count())
                .select_from(TaskIP)
                .where(TaskIP.task_id == task_id, TaskIP.stage == "threatbook_ready")
            )
            or 0
        )
        task.failed_count = unresolved
        task.status = TaskStatus.COMPLETED.value if unresolved == 0 else TaskStatus.PARTIAL_SUCCESS.value
        task.current_step = "archive_results"
        step.status = StepStatus.COMPLETED.value if unresolved == 0 else StepStatus.FAILED.value
        step.output_count = step.progress_current
        step.error_summary = None if unresolved == 0 else "部分IP未返回有效情报"
        step.finished_at = utcnow()
        archive = session.scalar(
            select(TaskStep).where(TaskStep.task_id == task_id, TaskStep.name == "archive_results")
        )
        archive.status = StepStatus.COMPLETED.value
        archive.started_at = archive.started_at or utcnow()
        archive.finished_at = utcnow()
        session.commit()
