from __future__ import annotations

from datetime import date, datetime, time, timedelta

from fastapi import APIRouter, Query, Request
from sqlalchemy import case, exists, func, or_, select, true

from xcheck.api.result_views import apply_threatbook_result_filters
from xcheck.models import Task, TaskIP, TaskStep, ThreatbookBatch, ThreatbookResult

router = APIRouter(prefix="/api/threatbook", tags=["threatbook"])


def _has_result_filter(*values: object) -> bool:
    return any(value is not None and value != "" for value in values)


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


@router.get("/history")
def list_threatbook_history(
    request: Request,
    q: str | None = None,
    malicious: bool | None = None,
    judgment: str | None = None,
    country: str | None = None,
    province: str | None = None,
    city: str | None = None,
    severity: str | None = None,
    confidence: str | None = None,
    status: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
):
    with request.app.state.session_factory() as session:
        task_query = select(Task).where(
            or_(
                exists(select(1).where(ThreatbookBatch.task_id == Task.id).correlate(Task)),
                exists(
                    select(1)
                    .where(
                        TaskStep.task_id == Task.id,
                        TaskStep.name == "threatbook_query",
                        TaskStep.started_at.is_not(None),
                    )
                    .correlate(Task)
                ),
            )
        )
        result_filters = (q, malicious, judgment, country, province, city, severity, confidence)
        if _has_result_filter(*result_filters):
            matching_result = (
                select(1)
                .select_from(TaskIP)
                .join(ThreatbookResult, ThreatbookResult.task_ip_id == TaskIP.id)
                .where(TaskIP.task_id == Task.id)
                .correlate(Task)
            )
            matching_result = apply_threatbook_result_filters(
                matching_result,
                q=q,
                malicious=malicious,
                judgment=judgment,
                country=country,
                province=province,
                city=city,
                severity=severity,
                confidence=confidence,
            )
            task_query = task_query.where(exists(matching_result))
        if status:
            task_query = task_query.where(Task.status == status)
        if date_from:
            task_query = task_query.where(Task.created_at >= datetime.combine(date_from, time.min))
        if date_to:
            exclusive_end = datetime.combine(date_to + timedelta(days=1), time.min)
            task_query = task_query.where(Task.created_at < exclusive_end)

        total = session.scalar(select(func.count()).select_from(task_query.subquery())) or 0
        tasks = session.scalars(
            task_query.order_by(Task.created_at.desc(), Task.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
        task_ids = [task.id for task in tasks]
        if not task_ids:
            return {"items": [], "total": total, "page": page, "page_size": page_size}

        count_rows = session.execute(
            select(
                TaskIP.task_id,
                func.count(ThreatbookResult.id),
                func.coalesce(
                    func.sum(case((ThreatbookResult.is_malicious.is_(True), 1), else_=0)), 0
                ),
            )
            .select_from(TaskIP)
            .join(ThreatbookResult, ThreatbookResult.task_ip_id == TaskIP.id)
            .where(TaskIP.task_id.in_(task_ids))
            .group_by(TaskIP.task_id)
        ).all()
        counts = {task_id: (completed, malicious_count) for task_id, completed, malicious_count in count_rows}

        labels_each = func.json_each(ThreatbookResult.judgments_json).table_valued("value", "type")
        label_counts = (
            select(
                TaskIP.task_id.label("task_id"),
                labels_each.c.value.label("value"),
                func.count().label("frequency"),
            )
            .select_from(TaskIP)
            .join(ThreatbookResult, ThreatbookResult.task_ip_id == TaskIP.id)
            .join(labels_each, true())
            .where(TaskIP.task_id.in_(task_ids), labels_each.c.type == "text")
            .group_by(TaskIP.task_id, labels_each.c.value)
            .subquery()
        )
        ranked_labels = select(
            label_counts.c.task_id,
            label_counts.c.value,
            func.row_number()
            .over(
                partition_by=label_counts.c.task_id,
                order_by=(label_counts.c.frequency.desc(), label_counts.c.value),
            )
            .label("position"),
            func.count().over(partition_by=label_counts.c.task_id).label("distinct_count"),
        ).subquery()
        label_rows = session.execute(
            select(ranked_labels)
            .where(ranked_labels.c.position <= 3)
            .order_by(ranked_labels.c.task_id, ranked_labels.c.position)
        ).all()
        labels: dict[str, list[str]] = {}
        label_remaining: dict[str, int] = {}
        for task_id_value, value, _position, distinct_count in label_rows:
            labels.setdefault(task_id_value, []).append(value)
            label_remaining[task_id_value] = max(0, distinct_count - 3)

        region = _region_expression()
        region_counts = (
            select(
                TaskIP.task_id.label("task_id"),
                region.label("value"),
                func.count().label("frequency"),
            )
            .select_from(TaskIP)
            .join(ThreatbookResult, ThreatbookResult.task_ip_id == TaskIP.id)
            .where(TaskIP.task_id.in_(task_ids), region != "")
            .group_by(TaskIP.task_id, region)
            .subquery()
        )
        ranked_regions = select(
            region_counts.c.task_id,
            region_counts.c.value,
            func.row_number()
            .over(
                partition_by=region_counts.c.task_id,
                order_by=(region_counts.c.frequency.desc(), region_counts.c.value),
            )
            .label("position"),
            func.count().over(partition_by=region_counts.c.task_id).label("distinct_count"),
        ).subquery()
        region_rows = session.execute(
            select(ranked_regions)
            .where(ranked_regions.c.position <= 2)
            .order_by(ranked_regions.c.task_id, ranked_regions.c.position)
        ).all()
        regions: dict[str, list[str]] = {}
        region_remaining: dict[str, int] = {}
        for task_id_value, value, _position, distinct_count in region_rows:
            regions.setdefault(task_id_value, []).append(value)
            region_remaining[task_id_value] = max(0, distinct_count - 2)

        step_rows = session.scalars(
            select(TaskStep).where(
                TaskStep.task_id.in_(task_ids), TaskStep.name == "threatbook_query"
            )
        ).all()
        steps = {step.task_id: step for step in step_rows}

        return {
            "items": [
                {
                    "task_id": task.id,
                    "source_name": task.original_filename or "手动输入",
                    "status": task.status,
                    "ready_count": task.threatbook_ready_count,
                    "completed_count": counts.get(task.id, (0, 0))[0],
                    "failed_count": task.failed_count,
                    "malicious_count": counts.get(task.id, (0, 0))[1],
                    "labels": labels.get(task.id, []),
                    "label_remaining_count": label_remaining.get(task.id, 0),
                    "regions": regions.get(task.id, []),
                    "region_remaining_count": region_remaining.get(task.id, 0),
                    "created_at": task.created_at,
                    "started_at": steps.get(task.id).started_at if task.id in steps else None,
                    "finished_at": steps.get(task.id).finished_at if task.id in steps else None,
                }
                for task in tasks
            ],
            "total": total,
            "page": page,
            "page_size": page_size,
        }


def _distinct_options(session, column, limit: int) -> list[str]:
    return list(
        session.scalars(
            select(column)
            .where(column.is_not(None), column != "")
            .group_by(column)
            .order_by(func.count().desc(), column)
            .limit(limit)
        )
    )


@router.get("/filter-options")
def threatbook_filter_options(request: Request, limit: int = Query(100, ge=1, le=200)):
    with request.app.state.session_factory() as session:
        labels_each = func.json_each(ThreatbookResult.judgments_json).table_valued("value", "type")
        labels = list(
            session.scalars(
                select(labels_each.c.value)
                .select_from(ThreatbookResult)
                .join(labels_each, true())
                .where(labels_each.c.type == "text", labels_each.c.value != "")
                .group_by(labels_each.c.value)
                .order_by(func.count().desc(), labels_each.c.value)
                .limit(limit)
            )
        )
        return {
            "labels": labels,
            "countries": _distinct_options(session, ThreatbookResult.country, limit),
            "provinces": _distinct_options(session, ThreatbookResult.province, limit),
            "cities": _distinct_options(session, ThreatbookResult.city, limit),
            "severities": _distinct_options(session, ThreatbookResult.severity, limit),
            "confidence_levels": _distinct_options(session, ThreatbookResult.confidence_level, limit),
        }
