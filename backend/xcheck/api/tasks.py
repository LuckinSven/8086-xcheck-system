from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update

from xcheck.models import (
    StepAttempt,
    StepStatus,
    Task,
    TaskIP,
    TaskStatus,
    TaskStep,
    ThreatbookBatch,
    ThreatbookResult,
    WhitelistResult,
)
from xcheck.schemas import TaskSummary
from xcheck.services.pipeline import create_file_task, create_manual_task
from xcheck.services.threatbook import parse_threatbook_execution_config, redact_secrets
from xcheck.services.whitelist import confirm_removal

router = APIRouter(prefix="/api/tasks", tags=["tasks"])

_THREATBOOK_CONFIG_BOUNDS = {
    "batch_size": (1, 100),
    "safe_ips_per_minute": (1, 1000),
    "daily_budget": (1, None),
    "max_retries": (0, 3),
}


class ManualTaskRequest(BaseModel):
    text: str = Field(min_length=1)


def _task_payload(task: Task) -> dict:
    return TaskSummary.model_validate(task).model_dump(mode="json")


def _safe_threatbook_config(snapshot: str) -> dict[str, int | None]:
    try:
        loaded = json.loads(snapshot)
    except (TypeError, json.JSONDecodeError):
        loaded = {}
    if not isinstance(loaded, dict):
        loaded = {}
    safe = {}
    for field, (minimum, maximum) in _THREATBOOK_CONFIG_BOUNDS.items():
        value = loaded.get(field)
        valid = (
            isinstance(value, int)
            and not isinstance(value, bool)
            and value >= minimum
            and (maximum is None or value <= maximum)
        )
        safe[field] = value if valid else None
    return safe


@router.post("/manual", status_code=202)
def create_manual(payload: ManualTaskRequest, request: Request):
    task_id = create_manual_task(request.app.state.session_factory, payload.text, request.app.state.settings)
    request.app.state.worker.submit_ingest(task_id)
    with request.app.state.session_factory() as session:
        return _task_payload(session.get(Task, task_id))


@router.post("/upload", status_code=202)
async def create_upload(
    request: Request,
    input_type: Annotated[str, Query(pattern="^(csv|access|attack)$")],
    file: Annotated[UploadFile, File()],
):
    original_name = Path(file.filename or "upload").name
    task_dir = request.app.state.settings.data_dir / "tasks" / uuid.uuid4().hex / "input"
    task_dir.mkdir(parents=True, exist_ok=True)
    safe_stem = re.sub(r"[^A-Za-z0-9._-]", "_", original_name) or "upload"
    path = task_dir / f"source-{safe_stem}"
    size = 0
    with path.open("wb") as output:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > request.app.state.settings.upload_max_bytes:
                path.unlink(missing_ok=True)
                raise HTTPException(413, "上传文件超过500 MB限制")
            output.write(chunk)
    task_id = create_file_task(
        request.app.state.session_factory,
        input_type,
        original_name,
        path,
        request.app.state.settings,
    )
    request.app.state.worker.submit_ingest(task_id)
    with request.app.state.session_factory() as session:
        return _task_payload(session.get(Task, task_id))


@router.get("")
def list_tasks(request: Request, page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=200)):
    with request.app.state.session_factory() as session:
        total = session.scalar(select(func.count()).select_from(Task)) or 0
        items = session.scalars(
            select(Task).order_by(Task.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        ).all()
        return {
            "items": [_task_payload(item) for item in items],
            "total": total,
            "page": page,
            "page_size": page_size,
        }


@router.get("/{task_id}")
def get_task(task_id: str, request: Request):
    with request.app.state.session_factory() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise HTTPException(404, "任务不存在")
        payload = _task_payload(task)
        payload["threatbook_config"] = _safe_threatbook_config(task.config_snapshot)
        payload["invalid_count"] = task.invalid_count
        payload["error_summary"] = task.error_summary
        payload["steps"] = [
            {
                "name": step.name,
                "status": step.status,
                "progress_current": step.progress_current,
                "progress_total": step.progress_total,
                "current_batch": step.current_batch,
                "total_batches": step.total_batches,
                "error_summary": step.error_summary,
                "started_at": step.started_at,
                "finished_at": step.finished_at,
            }
            for step in session.scalars(
                select(TaskStep).where(TaskStep.task_id == task_id).order_by(TaskStep.id)
            )
        ]
        return payload


@router.get("/{task_id}/original")
def download_original(task_id: str, request: Request):
    with request.app.state.session_factory() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise HTTPException(404, "任务不存在")
        if not task.stored_path:
            raise HTTPException(404, "手动输入任务没有原始文件")
        path = Path(task.stored_path)
        if not path.is_file():
            raise HTTPException(404, "原始文件不存在")
        return FileResponse(path, filename=Path(task.original_filename or "original").name)


@router.get("/{task_id}/diagnostics")
def task_diagnostics(
    task_id: str,
    request: Request,
    attempt_limit: int = Query(50, ge=1, le=200),
    batch_limit: int = Query(50, ge=1, le=200),
):
    with request.app.state.session_factory() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise HTTPException(404, "任务不存在")
        attempt_total = session.scalar(
            select(func.count()).select_from(StepAttempt).where(StepAttempt.task_id == task_id)
        ) or 0
        attempts = session.scalars(
            select(StepAttempt)
            .where(StepAttempt.task_id == task_id)
            .order_by(StepAttempt.started_at.desc(), StepAttempt.id.desc())
            .limit(attempt_limit)
        ).all()
        batch_total = session.scalar(
            select(func.count())
            .select_from(ThreatbookBatch)
            .where(ThreatbookBatch.task_id == task_id)
        ) or 0
        batches = session.execute(
            select(
                ThreatbookBatch,
                func.json_array_length(ThreatbookBatch.unresolved_json).label("unresolved_count"),
            )
            .where(ThreatbookBatch.task_id == task_id)
            .order_by(ThreatbookBatch.batch_number.desc())
            .limit(batch_limit)
        ).all()
        completed_step = session.scalar(
            select(TaskStep)
            .where(TaskStep.task_id == task_id, TaskStep.status == StepStatus.COMPLETED.value)
            .order_by(TaskStep.id.desc())
            .limit(1)
        )
        return {
            "task_id": task_id,
            "status": task.status,
            "current_step": task.current_step,
            "error_summary": task.error_summary,
            "last_successful_checkpoint": None if completed_step is None else completed_step.name,
            "attempt_total": attempt_total,
            "batch_total": batch_total,
            "attempt_limit": attempt_limit,
            "batch_limit": batch_limit,
            "attempts": [
                {
                    "id": item.id,
                    "step_name": item.step_name,
                    "batch_id": item.batch_id,
                    "attempt_number": item.attempt_number,
                    "status": item.status,
                    "http_status": item.http_status,
                    "response_code": item.response_code,
                    "safe_request": redact_secrets(json.loads(item.safe_request_json)),
                    "error_type": item.error_type,
                    "error_message": item.error_message,
                    "started_at": item.started_at,
                    "finished_at": item.finished_at,
                }
                for item in attempts
            ],
            "batches": [
                {
                    "id": batch.id,
                    "batch_number": batch.batch_number,
                    "status": batch.status,
                    "attempt_count": batch.attempt_count,
                    "response_code": batch.response_code,
                    "response_message": None
                    if batch.response_message is None
                    else (
                        "微步接口请求完成"
                        if batch.status == "completed"
                        else "微步接口请求失败"
                    ),
                    "unresolved_count": unresolved_count or 0,
                }
                for batch, unresolved_count in batches
            ],
        }


@router.post("/{task_id}/steps/{step_name}/retry", status_code=202)
def retry_step(task_id: str, step_name: str, request: Request):
    with request.app.state.session_factory() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise HTTPException(404, "任务不存在")
        if task.status not in {TaskStatus.FAILED.value, TaskStatus.PARTIAL_SUCCESS.value}:
            raise HTTPException(409, "只有失败或部分成功任务可以重试")
        step = session.scalar(select(TaskStep).where(TaskStep.task_id == task_id, TaskStep.name == step_name))
        if step is None:
            raise HTTPException(404, "任务节点不存在")
        if step_name == "threatbook_query":
            if not request.app.state.settings.threatbook_api_key:
                raise HTTPException(409, "后端尚未配置微步 API Key")
            try:
                parse_threatbook_execution_config(task.config_snapshot)
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from exc
        claim_values = {"status": TaskStatus.QUEUED.value, "error_summary": None}
        if step_name == "threatbook_query":
            claim_values["current_step"] = "threatbook_query"
        claimed = session.execute(
            update(Task)
            .where(
                Task.id == task_id,
                Task.status.in_([TaskStatus.FAILED.value, TaskStatus.PARTIAL_SUCCESS.value]),
            )
            .values(**claim_values)
        )
        if claimed.rowcount != 1:
            session.rollback()
            raise HTTPException(409, "任务已被其他请求领取")
        step.status = StepStatus.PENDING.value
        step.error_summary = None
        step.finished_at = None
        session.commit()
        session.refresh(task)
        if step_name == "threatbook_query":
            request.app.state.worker.submit_threatbook(task_id)
        else:
            request.app.state.worker.submit_ingest(task_id)
        return _task_payload(task)


@router.post("/{task_id}/actions/remove-whitelist")
def remove_whitelist(task_id: str, request: Request):
    try:
        task = confirm_removal(request.app.state.session_factory, task_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return _task_payload(task)


@router.post("/{task_id}/actions/start-threatbook", status_code=202)
def start_threatbook(task_id: str, request: Request):
    if not request.app.state.settings.threatbook_api_key:
        raise HTTPException(409, "后端尚未配置微步 API Key")
    with request.app.state.session_factory() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise HTTPException(404, "任务不存在")
        if task.status not in {"waiting_threatbook_confirmation", "paused_quota"}:
            raise HTTPException(409, "任务尚未进入微步查询阶段")
        try:
            parse_threatbook_execution_config(task.config_snapshot)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        claimed = session.execute(
            update(Task)
            .where(
                Task.id == task_id,
                Task.status.in_([TaskStatus.WAITING_THREATBOOK.value, TaskStatus.PAUSED_QUOTA.value]),
            )
            .values(status=TaskStatus.QUEUED.value, current_step="threatbook_query")
        )
        if claimed.rowcount != 1:
            session.rollback()
            raise HTTPException(409, "任务已被其他请求领取")
        session.commit()
        session.refresh(task)
        payload = _task_payload(task)
    request.app.state.worker.submit_threatbook(task_id)
    return payload


@router.get("/{task_id}/ips")
def list_ips(
    task_id: str,
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    stage: str | None = None,
):
    with request.app.state.session_factory() as session:
        query = select(TaskIP).where(TaskIP.task_id == task_id)
        count_query = select(func.count()).select_from(TaskIP).where(TaskIP.task_id == task_id)
        if stage:
            query = query.where(TaskIP.stage == stage)
            count_query = count_query.where(TaskIP.stage == stage)
        total = session.scalar(count_query) or 0
        rows = session.scalars(
            query.order_by(TaskIP.id).offset((page - 1) * page_size).limit(page_size)
        ).all()
        return {
            "items": [
                {
                    "id": row.id,
                    "ip": row.normalized_ip,
                    "ip_version": row.ip_version,
                    "is_public": row.is_public,
                    "stage": row.stage,
                    "occurrence_count": row.occurrence_count,
                    "first_position": row.first_position,
                    "last_position": row.last_position,
                }
                for row in rows
            ],
            "total": total,
            "page": page,
            "page_size": page_size,
        }


@router.get("/{task_id}/ips/{ip_id}")
def ip_diagnostics(task_id: str, ip_id: int, request: Request):
    with request.app.state.session_factory() as session:
        item = session.scalar(select(TaskIP).where(TaskIP.task_id == task_id, TaskIP.id == ip_id))
        if item is None:
            raise HTTPException(404, "IP记录不存在")
        whitelist = session.scalar(select(WhitelistResult).where(WhitelistResult.task_ip_id == item.id))
        threatbook = session.scalar(select(ThreatbookResult).where(ThreatbookResult.task_ip_id == item.id))
        return {
            "id": item.id,
            "ip": item.normalized_ip,
            "ip_version": item.ip_version,
            "is_public": item.is_public,
            "stage": item.stage,
            "occurrence_count": item.occurrence_count,
            "first_position": item.first_position,
            "last_position": item.last_position,
            "sample_positions": json.loads(item.sample_positions),
            "whitelist": None
            if whitelist is None
            else {
                "result_code": whitelist.result_code,
                "verdict": whitelist.verdict,
                "matches": json.loads(whitelist.matches_json),
                "request_id": whitelist.request_id,
            },
            "threatbook": None
            if threatbook is None
            else {
                "is_malicious": threatbook.is_malicious,
                "confidence_level": threatbook.confidence_level,
                "severity": threatbook.severity,
                "judgments": json.loads(threatbook.judgments_json),
                "batch_id": threatbook.batch_id,
                "country": threatbook.country,
                "province": threatbook.province,
                "city": threatbook.city,
                "carrier": threatbook.carrier,
                "asn_number": threatbook.asn_number,
                "asn_name": threatbook.asn_name,
                "scene": threatbook.scene,
                "update_time": threatbook.update_time,
                "permalink": threatbook.permalink,
            },
        }
