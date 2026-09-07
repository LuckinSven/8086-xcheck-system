from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import case, func, select, true
from sqlalchemy.orm import Session

from xcheck.models import DailyUsage, Task, TaskIP, TaskStatus, TaskStep, ThreatbookResult

RECENT_RISK_LIMIT = 8
RANK_LIMIT = 10
TASK_LIMIT = 8

ACTIVE_STATUSES = (
    TaskStatus.QUEUED.value,
    TaskStatus.RUNNING.value,
    TaskStatus.WAITING_WHITELIST.value,
    TaskStatus.WAITING_THREATBOOK.value,
    TaskStatus.PAUSED_QUOTA.value,
)
FAILED_STATUSES = (TaskStatus.FAILED.value, TaskStatus.PARTIAL_SUCCESS.value)


def _section(items: list[dict], **metadata: object) -> dict:
    return {"available": True, "items": items, **metadata}


def _day_start(value: date) -> datetime:
    return datetime.combine(value, datetime.min.time())


def _seven_day_trend(session: Session, *, malicious_only: bool = False) -> list[dict]:
    today = datetime.now(UTC).date()
    first_day = today - timedelta(days=6)
    if malicious_only:
        statement = (
            select(func.date(Task.created_at), func.count(ThreatbookResult.id))
            .select_from(ThreatbookResult)
            .join(TaskIP, TaskIP.id == ThreatbookResult.task_ip_id)
            .join(Task, Task.id == TaskIP.task_id)
            .where(
                ThreatbookResult.is_malicious.is_(True),
                Task.created_at >= _day_start(first_day),
            )
            .group_by(func.date(Task.created_at))
        )
        values = {str(day): int(count) for day, count in session.execute(statement)}
        return [
            {
                "date": (first_day + timedelta(days=offset)).isoformat(),
                "malicious": values.get((first_day + timedelta(days=offset)).isoformat(), 0),
            }
            for offset in range(7)
        ]

    statement = (
        select(
            func.date(Task.created_at),
            func.count(Task.id),
            func.coalesce(func.sum(Task.unique_count), 0),
            func.coalesce(func.sum(Task.malicious_count), 0),
        )
        .where(Task.created_at >= _day_start(first_day))
        .group_by(func.date(Task.created_at))
    )
    values = {
        str(day): (int(tasks), int(addresses), int(malicious))
        for day, tasks, addresses, malicious in session.execute(statement)
    }
    return [
        {
            "date": (first_day + timedelta(days=offset)).isoformat(),
            "tasks": values.get((first_day + timedelta(days=offset)).isoformat(), (0, 0, 0))[0],
            "addresses": values.get((first_day + timedelta(days=offset)).isoformat(), (0, 0, 0))[1],
            "malicious": values.get((first_day + timedelta(days=offset)).isoformat(), (0, 0, 0))[2],
        }
        for offset in range(7)
    ]


def _labels(raw_value: str) -> list[str]:
    try:
        value = json.loads(raw_value)
    except (TypeError, json.JSONDecodeError):
        return []
    return [item[:128] for item in value[:10] if isinstance(item, str)] if isinstance(value, list) else []


def _safe_test_summary(raw_value: str) -> dict:
    try:
        value = json.loads(raw_value)
    except (TypeError, json.JSONDecodeError):
        value = {}
    if not isinstance(value, dict) or value.get("status") not in {"success", "failed"}:
        return {"status": "untested", "tested_at": None, "latency_ms": None}
    tested_at = value.get("tested_at")
    latency_ms = value.get("latency_ms")
    return {
        "status": value["status"],
        "tested_at": tested_at[:64] if isinstance(tested_at, str) else None,
        "latency_ms": latency_ms if isinstance(latency_ms, int) and 0 <= latency_ms <= 3_600_000 else None,
        "error_code": value.get("error_code")[:128]
        if isinstance(value.get("error_code"), str)
        else None,
    }


def _overview(session: Session) -> tuple[dict, dict]:
    totals = session.execute(
        select(
            func.count(Task.id),
            func.coalesce(func.sum(Task.unique_count), 0),
            func.coalesce(func.sum(Task.malicious_count), 0),
            func.coalesce(func.sum(case((Task.status.in_(ACTIVE_STATUSES), 1), else_=0)), 0),
            func.coalesce(func.sum(case((Task.status.in_(FAILED_STATUSES), 1), else_=0)), 0),
        )
    ).one()

    recent_rows = session.execute(
        select(
            Task.id,
            Task.created_at,
            TaskIP.normalized_ip,
            ThreatbookResult.confidence_level,
            ThreatbookResult.severity,
            ThreatbookResult.judgments_json,
            ThreatbookResult.country,
            ThreatbookResult.province,
            ThreatbookResult.city,
        )
        .select_from(ThreatbookResult)
        .join(TaskIP, TaskIP.id == ThreatbookResult.task_ip_id)
        .join(Task, Task.id == TaskIP.task_id)
        .where(ThreatbookResult.is_malicious.is_(True))
        .order_by(Task.created_at.desc(), ThreatbookResult.id)
        .limit(RECENT_RISK_LIMIT)
    ).all()
    recent_risks = [
        {
            "task_id": task_id,
            "created_at": created_at,
            "ip": normalized_ip,
            "confidence": confidence,
            "severity": severity,
            "labels": _labels(judgments_json),
            "country": country,
            "province": province,
            "city": city,
        }
        for (
            task_id,
            created_at,
            normalized_ip,
            confidence,
            severity,
            judgments_json,
            country,
            province,
            city,
        ) in recent_rows
    ]

    attention_rows = session.execute(
        select(Task.id, Task.status, Task.current_step, Task.error_summary, Task.updated_at)
        .where(Task.status.in_(FAILED_STATUSES))
        .order_by(Task.updated_at.desc(), Task.id)
        .limit(TASK_LIMIT)
    ).all()
    attention = [
        {
            "task_id": task_id,
            "status": status,
            "current_step": current_step,
            "error_summary": error_summary,
            "updated_at": updated_at,
        }
        for task_id, status, current_step, error_summary, updated_at in attention_rows
    ]

    summary = {
        "total_tasks": int(totals[0]),
        "total_unique_ips": int(totals[1]),
        "malicious_ips": int(totals[2]),
        "active_tasks": int(totals[3]),
        "failed_tasks": int(totals[4]),
    }
    sections = {
        "trend": _section(_seven_day_trend(session)),
        "recent_risks": _section(recent_risks, limit=RECENT_RISK_LIMIT),
        "attention": _section(attention, limit=TASK_LIMIT),
    }
    return summary, sections


def _ranked_values(session: Session, column, cutoff: datetime) -> list[dict]:
    rows = session.execute(
        select(column, func.count(ThreatbookResult.id).label("frequency"))
        .select_from(ThreatbookResult)
        .join(TaskIP, TaskIP.id == ThreatbookResult.task_ip_id)
        .join(Task, Task.id == TaskIP.task_id)
        .where(
            ThreatbookResult.is_malicious.is_(True),
            Task.created_at >= cutoff,
            column.is_not(None),
            column != "",
        )
        .group_by(column)
        .order_by(func.count(ThreatbookResult.id).desc(), column)
        .limit(RANK_LIMIT)
    ).all()
    return [{"name": name, "count": int(count)} for name, count in rows]


def _region_expression():
    country = func.coalesce(func.nullif(ThreatbookResult.country, ""), "")
    province = case(
        (func.nullif(ThreatbookResult.province, "").is_not(None), " / " + ThreatbookResult.province),
        else_="",
    )
    city = case(
        (func.nullif(ThreatbookResult.city, "").is_not(None), " / " + ThreatbookResult.city),
        else_="",
    )
    return func.trim(country + province + city, " /")


def _landscape(session: Session) -> tuple[dict, dict]:
    cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=24)
    malicious_last_day = session.scalar(
        select(func.count(ThreatbookResult.id))
        .select_from(ThreatbookResult)
        .join(TaskIP, TaskIP.id == ThreatbookResult.task_ip_id)
        .join(Task, Task.id == TaskIP.task_id)
        .where(ThreatbookResult.is_malicious.is_(True), Task.created_at >= cutoff)
    ) or 0
    total_malicious = session.scalar(
        select(func.count(ThreatbookResult.id)).where(ThreatbookResult.is_malicious.is_(True))
    ) or 0

    region = _region_expression()
    countries = _ranked_values(session, ThreatbookResult.country, cutoff)
    regions = _ranked_values(session, region, cutoff)
    severities = _ranked_values(session, ThreatbookResult.severity, cutoff)

    labels_each = func.json_each(ThreatbookResult.judgments_json).table_valued("value", "type")
    label_rows = session.execute(
        select(labels_each.c.value, func.count().label("frequency"))
        .select_from(ThreatbookResult)
        .join(TaskIP, TaskIP.id == ThreatbookResult.task_ip_id)
        .join(Task, Task.id == TaskIP.task_id)
        .join(labels_each, true())
        .where(
            ThreatbookResult.is_malicious.is_(True),
            Task.created_at >= cutoff,
            labels_each.c.type == "text",
        )
        .group_by(labels_each.c.value)
        .order_by(func.count().desc(), labels_each.c.value)
        .limit(RANK_LIMIT)
    ).all()
    labels = [{"name": name, "count": int(count)} for name, count in label_rows]

    summary = {
        "malicious_last_24h": int(malicious_last_day),
        "total_malicious": int(total_malicious),
        "affected_countries": len(countries),
    }
    sections = {
        "countries": _section(countries, limit=RANK_LIMIT),
        "regions": _section(regions, limit=RANK_LIMIT),
        "labels": _section(labels, limit=RANK_LIMIT),
        "severities": _section(severities, limit=RANK_LIMIT),
        "trend": _section(_seven_day_trend(session, malicious_only=True)),
    }
    return summary, sections


def _operations(session: Session, settings, *, worker_ready: bool, database_ready: bool) -> tuple[dict, dict]:
    status_rows = session.execute(select(Task.status, func.count(Task.id)).group_by(Task.status)).all()
    status_counts = {status.value: 0 for status in TaskStatus}
    status_counts.update({status: int(count) for status, count in status_rows})
    backlog = sum(status_counts[status] for status in ACTIVE_STATUSES)

    progress = session.execute(
        select(
            func.coalesce(func.sum(TaskStep.progress_current), 0),
            func.coalesce(func.sum(TaskStep.progress_total), 0),
        )
        .select_from(TaskStep)
        .join(Task, Task.id == TaskStep.task_id)
        .where(TaskStep.name == "threatbook_query", Task.status.in_(ACTIVE_STATUSES))
    ).one()
    current, total = int(progress[0]), int(progress[1])
    progress_summary = {
        "current": current,
        "total": total,
        "percent": round(current * 100 / total) if total else 0,
    }

    daily_usage = session.scalar(
        select(DailyUsage.successful_ips).where(DailyUsage.usage_date == date.today())
    ) or 0

    failed_rows = session.execute(
        select(
            TaskStep.task_id,
            TaskStep.name,
            TaskStep.error_summary,
            TaskStep.progress_current,
            TaskStep.progress_total,
            TaskStep.started_at,
        )
        .where(TaskStep.status == "failed")
        .order_by(TaskStep.started_at.desc(), TaskStep.id.desc())
        .limit(TASK_LIMIT)
    ).all()
    failed_nodes = [
        {
            "task_id": task_id,
            "step": name,
            "error_summary": error_summary,
            "current": progress_current,
            "total": progress_total,
            "started_at": started_at,
        }
        for task_id, name, error_summary, progress_current, progress_total, started_at in failed_rows
    ]

    active_rows = session.execute(
        select(
            Task.id,
            Task.status,
            Task.current_step,
            Task.unique_count,
            Task.created_at,
            TaskStep.progress_current,
            TaskStep.progress_total,
        )
        .outerjoin(
            TaskStep,
            (TaskStep.task_id == Task.id) & (TaskStep.name == "threatbook_query"),
        )
        .where(Task.status.in_(ACTIVE_STATUSES))
        .order_by(Task.created_at, Task.id)
        .limit(TASK_LIMIT)
    ).all()
    active_tasks = [
        {
            "task_id": task_id,
            "status": status,
            "current_step": current_step,
            "unique_count": unique_count,
            "created_at": created_at,
            "current": step_current or 0,
            "total": step_total or 0,
        }
        for task_id, status, current_step, unique_count, created_at, step_current, step_total in active_rows
    ]

    integration_health = [
        {"name": "whitelist", **_safe_test_summary(settings.whitelist_test_summary)},
        {
            "name": "threatbook",
            "credential_configured": bool(settings.threatbook_api_key),
            **_safe_test_summary(settings.threatbook_test_summary),
        },
    ]
    summary = {
        "status_counts": status_counts,
        "backlog": backlog,
        "progress": progress_summary,
        "daily_usage": int(daily_usage),
        "daily_remaining": max(0, settings.threatbook_daily_budget - int(daily_usage)),
        "worker_status": "ready" if worker_ready else "unavailable",
        "database_status": "ready" if database_ready else "unavailable",
    }
    sections = {
        "active_tasks": _section(active_tasks, limit=TASK_LIMIT),
        "failed_nodes": _section(failed_nodes, limit=TASK_LIMIT),
        "integration_health": _section(integration_health),
        "configuration": _section(
            [
                {"name": "batch_size", "value": settings.threatbook_batch_size},
                {"name": "safe_rate", "value": settings.threatbook_safe_ips_per_minute},
                {"name": "daily_budget", "value": settings.threatbook_daily_budget},
            ]
        ),
    }
    return summary, sections


def build_dashboard(
    session: Session,
    settings,
    mode: str,
    *,
    worker_ready: bool = True,
    database_ready: bool = True,
) -> dict:
    if mode == "overview":
        summary, sections = _overview(session)
    elif mode == "landscape":
        summary, sections = _landscape(session)
    else:
        summary, sections = _operations(
            session,
            settings,
            worker_ready=worker_ready,
            database_ready=database_ready,
        )
    return {
        "mode": mode,
        "generated_at": datetime.now(UTC),
        "summary": summary,
        "sections": sections,
    }
