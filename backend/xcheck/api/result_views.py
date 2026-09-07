from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import Select, case, func, select

from xcheck.models import Task, TaskIP, ThreatbookBatch, ThreatbookResult, WhitelistResult

router = APIRouter(prefix="/api/tasks", tags=["results"])

_VERDICT_CATEGORIES = {
    "active": "当前名单",
    "reference": "历史名单",
    "inactive": "失效名单",
    "not_found": "未命中",
}
_HIT_CODES = {"active", "reference", "inactive"}


def _json_string_like(value: str) -> str:
    encoded = json.dumps(value, ensure_ascii=False)
    escaped = encoded.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def apply_threatbook_result_filters(
    query: Select,
    *,
    q: str | None,
    malicious: bool | None,
    judgment: str | None,
    country: str | None,
    province: str | None,
    city: str | None,
    severity: str | None,
    confidence: str | None,
) -> Select:
    if q:
        query = query.where(TaskIP.normalized_ip.contains(q, autoescape=True))
    if malicious is not None:
        query = query.where(ThreatbookResult.is_malicious.is_(malicious))
    if judgment:
        query = query.where(
            ThreatbookResult.judgments_json.like(_json_string_like(judgment), escape="\\")
        )
    if country:
        query = query.where(ThreatbookResult.country == country)
    if province:
        query = query.where(ThreatbookResult.province == province)
    if city:
        query = query.where(ThreatbookResult.city == city)
    if severity:
        query = query.where(ThreatbookResult.severity == severity)
    if confidence:
        query = query.where(ThreatbookResult.confidence_level == confidence)
    return query


def _json_list(value: str) -> list:
    loaded = json.loads(value)
    return loaded if isinstance(loaded, list) else []


def whitelist_category(result_code: str) -> str:
    return _VERDICT_CATEGORIES.get(result_code, "异常")


@router.get("/{task_id}/whitelist-results")
def list_whitelist_results(
    task_id: str,
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    verdict: str | None = None,
):
    with request.app.state.session_factory() as session:
        if session.get(Task, task_id) is None:
            raise HTTPException(404, "任务不存在")

        query = (
            select(TaskIP, WhitelistResult)
            .join(WhitelistResult, WhitelistResult.task_ip_id == TaskIP.id)
            .where(TaskIP.task_id == task_id)
        )
        count_query = (
            select(func.count())
            .select_from(TaskIP)
            .join(WhitelistResult, WhitelistResult.task_ip_id == TaskIP.id)
            .where(TaskIP.task_id == task_id)
        )
        if verdict:
            matching_codes = [
                result_code
                for result_code in {*_VERDICT_CATEGORIES, "invalid"}
                if verdict in {result_code, whitelist_category(result_code)}
            ]
            if matching_codes:
                query = query.where(WhitelistResult.result_code.in_(matching_codes))
                count_query = count_query.where(WhitelistResult.result_code.in_(matching_codes))
            else:
                query = query.where(False)
                count_query = count_query.where(False)

        total = session.scalar(count_query) or 0
        rows = session.execute(
            query.order_by(TaskIP.id).offset((page - 1) * page_size).limit(page_size)
        ).all()
        summary_row = session.execute(
            select(
                func.count(),
                func.coalesce(func.sum(case((WhitelistResult.result_code.in_(_HIT_CODES), 1), else_=0)), 0),
                func.coalesce(func.sum(case((WhitelistResult.result_code == "not_found", 1), else_=0)), 0),
            )
            .select_from(TaskIP)
            .join(WhitelistResult, WhitelistResult.task_ip_id == TaskIP.id)
            .where(TaskIP.task_id == task_id)
        ).one()
        summary_total, hit_count, clear_count = summary_row
        return {
            "summary": {
                "total": summary_total,
                "hit": hit_count,
                "clear": clear_count,
                "error": summary_total - hit_count - clear_count,
            },
            "items": [
                {
                    "ip": task_ip.normalized_ip,
                    "category": whitelist_category(result.result_code),
                    "result_code": result.result_code,
                    "verdict": result.verdict,
                    "matches": json.loads(result.matches_json),
                    "request_id": result.request_id,
                }
                for task_ip, result in rows
            ],
            "total": total,
            "page": page,
            "page_size": page_size,
        }


@router.get("/{task_id}/threatbook/batches")
def list_threatbook_batches(
    task_id: str,
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    with request.app.state.session_factory() as session:
        if session.get(Task, task_id) is None:
            raise HTTPException(404, "任务不存在")
        base = select(ThreatbookBatch).where(ThreatbookBatch.task_id == task_id)
        total = session.scalar(
            select(func.count()).select_from(ThreatbookBatch).where(ThreatbookBatch.task_id == task_id)
        ) or 0
        batches = session.scalars(
            base.order_by(ThreatbookBatch.batch_number)
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
        items = []
        for batch in batches:
            address_count = len(_json_list(batch.addresses_json))
            unresolved_count = len(_json_list(batch.unresolved_json))
            items.append(
                {
                    "id": batch.id,
                    "batch_number": batch.batch_number,
                    "status": batch.status,
                    "address_count": address_count,
                    "resolved_count": max(0, address_count - unresolved_count),
                    "unresolved_count": unresolved_count,
                    "attempt_count": batch.attempt_count,
                    "response_code": batch.response_code,
                    "response_message": None
                    if batch.response_message is None
                    else (
                        "微步接口请求完成"
                        if batch.status == "completed"
                        else "微步接口请求失败"
                    ),
                    "created_at": batch.created_at,
                    "finished_at": batch.finished_at,
                }
            )
        return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/{task_id}/threatbook/results")
def list_threatbook_results(
    task_id: str,
    request: Request,
    q: str | None = None,
    malicious: bool | None = None,
    judgment: str | None = None,
    country: str | None = None,
    province: str | None = None,
    city: str | None = None,
    severity: str | None = None,
    confidence: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    with request.app.state.session_factory() as session:
        if session.get(Task, task_id) is None:
            raise HTTPException(404, "任务不存在")
        query = (
            select(TaskIP, ThreatbookResult)
            .join(ThreatbookResult, ThreatbookResult.task_ip_id == TaskIP.id)
            .where(TaskIP.task_id == task_id)
        )
        query = apply_threatbook_result_filters(
            query,
            q=q,
            malicious=malicious,
            judgment=judgment,
            country=country,
            province=province,
            city=city,
            severity=severity,
            confidence=confidence,
        )
        total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
        rows = session.execute(
            query.order_by(TaskIP.id).offset((page - 1) * page_size).limit(page_size)
        ).all()
        return {
            "items": [
                {
                    "id": result.id,
                    "task_ip_id": task_ip.id,
                    "batch_id": result.batch_id,
                    "ip": task_ip.normalized_ip,
                    "is_malicious": result.is_malicious,
                    "confidence_level": result.confidence_level,
                    "severity": result.severity,
                    "judgments": _json_list(result.judgments_json),
                    "country": result.country,
                    "province": result.province,
                    "city": result.city,
                    "carrier": result.carrier,
                    "asn_number": result.asn_number,
                    "asn_name": result.asn_name,
                    "scene": result.scene,
                    "update_time": result.update_time,
                    "permalink": result.permalink,
                }
                for task_ip, result in rows
            ],
            "total": total,
            "page": page,
            "page_size": page_size,
        }
