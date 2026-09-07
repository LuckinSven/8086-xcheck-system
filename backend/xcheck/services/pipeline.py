from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import Session, sessionmaker

from xcheck.models import InputError, StepStatus, Task, TaskIP, TaskStatus, TaskStep, utcnow

from .parsers import ExtractedValue, ParseError, iter_file_ips, iter_manual_ips

STEP_NAMES = [
    "save_input",
    "parse_input",
    "extract_ips",
    "validate_ips",
    "deduplicate_ips",
    "whitelist_query",
    "remove_whitelist",
    "filter_non_public",
    "threatbook_query",
    "archive_results",
]


def _config_snapshot(settings=None) -> str:
    if settings is None:
        return "{}"
    return json.dumps(
        {
            "batch_size": settings.threatbook_batch_size,
            "safe_ips_per_minute": settings.threatbook_safe_ips_per_minute,
            "daily_budget": settings.threatbook_daily_budget,
            "max_retries": settings.threatbook_max_retries,
        },
        ensure_ascii=False,
    )


def create_manual_task(factory: sessionmaker[Session], text: str, settings=None) -> str:
    if not text.strip():
        raise ValueError("请输入至少一个IP地址")
    with factory() as session:
        task = Task(input_type="manual", manual_text=text, config_snapshot=_config_snapshot(settings))
        session.add(task)
        session.flush()
        session.add_all([TaskStep(task_id=task.id, name=name) for name in STEP_NAMES])
        session.commit()
        return task.id


def create_file_task(
    factory: sessionmaker[Session], input_type: str, original_filename: str, stored_path: Path, settings=None
) -> str:
    with factory() as session:
        task = Task(
            input_type=input_type,
            original_filename=original_filename,
            stored_path=str(stored_path),
            config_snapshot=_config_snapshot(settings),
        )
        session.add(task)
        session.flush()
        session.add_all([TaskStep(task_id=task.id, name=name) for name in STEP_NAMES])
        session.commit()
        return task.id


def _set_step(session: Session, task: Task, name: str, status: str, **values) -> TaskStep:
    step = session.scalar(select(TaskStep).where(TaskStep.task_id == task.id, TaskStep.name == name))
    if step is None:
        step = TaskStep(task_id=task.id, name=name)
        session.add(step)
    step.status = status
    task.current_step = name
    if status == StepStatus.RUNNING.value and step.started_at is None:
        step.started_at = utcnow()
    if status in {StepStatus.COMPLETED.value, StepStatus.FAILED.value}:
        step.finished_at = utcnow()
    for key, value in values.items():
        setattr(step, key, value)
    return step


def _iter_task_values(task: Task, settings) -> Iterable[ExtractedValue]:
    if task.input_type == "manual":
        return iter_manual_ips(task.manual_text or "")
    path = Path(task.stored_path or "")
    if task.input_type in {"attack", "access", "csv"}:
        return iter_file_ips(
            path,
            task.input_type,
            settings.zip_max_members,
            settings.zip_max_uncompressed_bytes,
        )
    raise ParseError(f"不支持的输入类型：{task.input_type}")


def _flush_chunk(session: Session, task_id: str, aggregate: dict[str, dict]) -> None:
    if not aggregate:
        return
    rows = [
        {
            "task_id": task_id,
            "raw_value": item["raw_value"],
            "normalized_ip": normalized,
            "ip_version": item["ip_version"],
            "is_public": item["is_public"],
            "stage": "validated",
            "occurrence_count": item["count"],
            "first_position": item["first_position"],
            "last_position": item["last_position"],
            "sample_positions": json.dumps(item["samples"], ensure_ascii=False),
        }
        for normalized, item in aggregate.items()
    ]
    statement = insert(TaskIP)
    statement = statement.on_conflict_do_update(
        index_elements=[TaskIP.task_id, TaskIP.normalized_ip],
        set_={
            "occurrence_count": TaskIP.occurrence_count + statement.excluded.occurrence_count,
            "last_position": statement.excluded.last_position,
            "sample_positions": statement.excluded.sample_positions,
        },
    )
    session.execute(statement, rows)
    session.commit()


def ingest_task(factory: sessionmaker[Session], task_id: str, settings=None) -> None:
    if settings is None:
        from xcheck.config import get_settings

        settings = get_settings()
    with factory() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise ValueError("任务不存在")
        session.execute(delete(TaskIP).where(TaskIP.task_id == task_id))
        session.execute(delete(InputError).where(InputError.task_id == task_id))
        task.status = TaskStatus.RUNNING.value
        _set_step(session, task, "parse_input", StepStatus.RUNNING.value)
        session.commit()

        raw_count = valid_count = invalid_count = 0
        aggregate: dict[str, dict] = {}
        try:
            for extracted in _iter_task_values(task, settings):
                raw_count += 1
                if extracted.parse_error:
                    invalid_count += 1
                    session.add(
                        InputError(
                            task_id=task_id,
                            raw_value=extracted.raw_value,
                            position=extracted.position,
                            reason=extracted.parse_error,
                        )
                    )
                    continue
                try:
                    address = ipaddress.ip_address(extracted.raw_value.strip())
                except ValueError:
                    invalid_count += 1
                    session.add(
                        InputError(
                            task_id=task_id,
                            raw_value=extracted.raw_value,
                            position=extracted.position,
                            reason="IP格式错误",
                        )
                    )
                    continue
                valid_count += 1
                normalized = str(address)
                item = aggregate.setdefault(
                    normalized,
                    {
                        "raw_value": extracted.raw_value,
                        "ip_version": address.version,
                        "is_public": address.is_global,
                        "count": 0,
                        "first_position": extracted.position,
                        "last_position": extracted.position,
                        "samples": [],
                    },
                )
                item["count"] += 1
                item["last_position"] = extracted.position
                if len(item["samples"]) < 5:
                    item["samples"].append(extracted.position)
                if len(aggregate) >= 5000:
                    _flush_chunk(session, task_id, aggregate)
                    aggregate = {}
            _flush_chunk(session, task_id, aggregate)
            task = session.get(Task, task_id)
            task.raw_count = raw_count
            task.valid_count = valid_count
            task.invalid_count = invalid_count
            task.unique_count = (
                session.scalar(
                    select(TaskIP.id).where(TaskIP.task_id == task_id).with_only_columns(TaskIP.id)
                )
                and session.query(TaskIP).filter(TaskIP.task_id == task_id).count()
                or 0
            )
            for name in ("parse_input", "extract_ips", "validate_ips", "deduplicate_ips"):
                _set_step(
                    session,
                    task,
                    name,
                    StepStatus.COMPLETED.value,
                    input_count=raw_count,
                    output_count=task.unique_count,
                )
            task.status = TaskStatus.RUNNING.value
            session.commit()
        except Exception as exc:
            task = session.get(Task, task_id)
            task.status = TaskStatus.FAILED.value
            task.error_summary = str(exc)
            _set_step(session, task, "parse_input", StepStatus.FAILED.value, error_summary=str(exc))
            session.commit()
            raise
