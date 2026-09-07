from __future__ import annotations

import json

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from xcheck.models import StepAttempt, StepStatus, Task, TaskIP, TaskStatus, TaskStep, WhitelistResult, utcnow


def classify_whitelist_result(result_code: str) -> str:
    if result_code in {"active", "reference", "inactive"}:
        return "whitelist_removed"
    if result_code == "not_found":
        return "whitelist_clear"
    return "invalid"


class WhitelistClient:
    def __init__(self, url: str, timeout: float = 30.0, transport=None):
        self.url = url
        self.timeout = timeout
        self.transport = transport

    def query(self, addresses: list[str]) -> dict:
        with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
            response = client.post(self.url, json={"addresses": addresses})
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            raise ValueError("白名单API返回结构不正确")
        return payload


def run_whitelist(factory: sessionmaker[Session], task_id: str, client: WhitelistClient) -> None:
    auto_advance = False
    with factory() as session:
        task = session.get(Task, task_id)
        step = session.scalar(
            select(TaskStep).where(TaskStep.task_id == task_id, TaskStep.name == "whitelist_query")
        )
        step.status = StepStatus.RUNNING.value
        step.started_at = step.started_at or utcnow()
        task.current_step = "whitelist_query"
        task.status = TaskStatus.RUNNING.value
        ips = session.scalars(select(TaskIP).where(TaskIP.task_id == task_id).order_by(TaskIP.id)).all()
        step.total_batches = (len(ips) + 499) // 500
        session.commit()

        completed_result_count = hit_count = abnormal_count = 0
        all_not_found = True
        try:
            for offset in range(0, len(ips), 500):
                batch = ips[offset : offset + 500]
                attempt = StepAttempt(
                    task_id=task_id,
                    step_name="whitelist_query",
                    attempt_number=1,
                    status="running",
                    safe_request_json=json.dumps({"count": len(batch)}),
                )
                session.add(attempt)
                session.commit()
                payload = client.query([item.normalized_ip for item in batch])
                by_query = {item["query"]: item for item in payload["results"]}
                batch_abnormal_count = 0
                for task_ip in batch:
                    result = by_query.get(task_ip.normalized_ip)
                    if result is None:
                        raise ValueError(f"白名单API缺少结果：{task_ip.normalized_ip}")
                    result_code = result["result_code"]
                    if result_code in {"active", "reference", "inactive"}:
                        hit_count += 1
                    if result_code != "not_found":
                        all_not_found = False
                    if result_code not in {"active", "reference", "inactive", "not_found"}:
                        abnormal_count += 1
                        batch_abnormal_count += 1
                    task_ip.stage = (
                        "whitelist_hit"
                        if result_code in {"active", "reference", "inactive"}
                        else classify_whitelist_result(result_code)
                    )
                    session.add(
                        WhitelistResult(
                            task_ip_id=task_ip.id,
                            request_id=payload.get("request_id"),
                            result_code=result_code,
                            verdict=result.get("verdict", ""),
                            matches_json=json.dumps(result.get("matches", []), ensure_ascii=False),
                            raw_json=json.dumps(result, ensure_ascii=False),
                        )
                    )
                    completed_result_count += 1
                attempt.status = "failed" if batch_abnormal_count else "completed"
                if batch_abnormal_count:
                    attempt.error_type = "InvalidWhitelistVerdict"
                    attempt.error_message = f"白名单API返回 {batch_abnormal_count} 条异常结论"
                attempt.finished_at = utcnow()
                step.current_batch = offset // 500 + 1
                step.progress_current = min(offset + 500, len(ips))
                session.commit()
            if abnormal_count:
                task.status = TaskStatus.FAILED.value
                task.error_summary = f"白名单API返回 {abnormal_count} 条异常结论"
                step.status = StepStatus.FAILED.value
                step.error_summary = task.error_summary
            else:
                task.status = TaskStatus.WAITING_WHITELIST.value
                step.status = StepStatus.COMPLETED.value
            step.finished_at = utcnow()
            step.output_count = len(ips)
            session.commit()
            auto_advance = (
                abnormal_count == 0
                and completed_result_count == len(ips)
                and hit_count == 0
                and all_not_found
            )
        except Exception as exc:
            task.status = TaskStatus.FAILED.value
            task.error_summary = str(exc)
            step.status = StepStatus.FAILED.value
            step.error_summary = str(exc)
            step.finished_at = utcnow()
            session.commit()
            raise

    if auto_advance:
        confirm_removal(factory, task_id)


def confirm_removal(factory: sessionmaker[Session], task_id: str) -> Task:
    with factory() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise ValueError("任务不存在")
        if task.status == TaskStatus.WAITING_THREATBOOK.value:
            return task
        if task.status != TaskStatus.WAITING_WHITELIST.value:
            raise ValueError("任务尚未完成查白")
        ips = session.scalars(select(TaskIP).where(TaskIP.task_id == task_id)).all()
        removed = ready = 0
        for task_ip in ips:
            if task_ip.stage == "whitelist_hit":
                task_ip.stage = "whitelist_removed"
                removed += 1
            elif task_ip.stage == "whitelist_clear":
                if task_ip.is_public:
                    task_ip.stage = "threatbook_ready"
                    ready += 1
                else:
                    task_ip.stage = "non_public"
        task.whitelist_removed_count = removed
        task.threatbook_ready_count = ready
        task.status = TaskStatus.WAITING_THREATBOOK.value
        task.current_step = "filter_non_public"
        for name in ("remove_whitelist", "filter_non_public"):
            step = session.scalar(select(TaskStep).where(TaskStep.task_id == task_id, TaskStep.name == name))
            step.status = StepStatus.COMPLETED.value
            step.started_at = step.started_at or utcnow()
            step.finished_at = utcnow()
        session.commit()
        session.refresh(task)
        return task
