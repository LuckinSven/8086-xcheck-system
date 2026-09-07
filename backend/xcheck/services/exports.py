from __future__ import annotations

import io
from collections.abc import Iterator

from openpyxl import Workbook
from sqlalchemy import select

from xcheck.models import InputError, TaskIP, ThreatbookResult, WhitelistResult

STAGE_FILTERS = {
    "extracted": None,
    "valid": None,
    "invalid": "invalid",
    "deduplicated": None,
    "whitelist_all": None,
    "whitelist_hits": "whitelist_removed",
    "after_whitelist": "whitelist_clear",
    "non_public": "non_public",
    "threatbook_ready": "threatbook_ready",
    "threatbook_complete": "threatbook_complete",
    "malicious": "malicious",
    "high_confidence_malicious": "high_confidence_malicious",
    "non_malicious": "non_malicious",
    "failed": "failed",
}


HEADERS = ["IP", "IP版本", "出现次数", "是否公网", "阶段", "首次位置", "最后位置"]
ERROR_HEADERS = ["原始值", "来源位置", "错误原因"]


def rows_for_stage(session, task_id: str, stage: str) -> Iterator[list]:
    if stage not in STAGE_FILTERS:
        raise KeyError(stage)
    if stage == "invalid":
        for item in session.scalars(
            select(InputError).where(InputError.task_id == task_id).order_by(InputError.id)
        ).yield_per(1000):
            yield [item.raw_value, item.position, item.reason]
        return
    query = select(TaskIP).where(TaskIP.task_id == task_id)
    stage_filter = STAGE_FILTERS[stage]
    if stage == "whitelist_all":
        query = query.join(WhitelistResult, WhitelistResult.task_ip_id == TaskIP.id)
    elif stage == "whitelist_hits":
        query = query.join(WhitelistResult, WhitelistResult.task_ip_id == TaskIP.id).where(
            WhitelistResult.result_code.in_(["active", "reference", "inactive"])
        )
    elif stage == "after_whitelist":
        query = query.join(WhitelistResult, WhitelistResult.task_ip_id == TaskIP.id).where(
            WhitelistResult.result_code == "not_found"
        )
    elif stage in {"threatbook_complete", "malicious", "high_confidence_malicious", "non_malicious"}:
        query = query.join(ThreatbookResult, ThreatbookResult.task_ip_id == TaskIP.id)
        if stage == "malicious":
            query = query.where(ThreatbookResult.is_malicious.is_(True))
        elif stage == "high_confidence_malicious":
            query = query.where(
                ThreatbookResult.is_malicious.is_(True),
                ThreatbookResult.confidence_level == "high",
            )
        elif stage == "non_malicious":
            query = query.where(ThreatbookResult.is_malicious.is_(False))
    elif stage_filter in {"whitelist_removed", "whitelist_clear", "non_public", "threatbook_ready"}:
        query = query.where(TaskIP.stage == stage_filter)
    for item in session.scalars(query.order_by(TaskIP.id)).yield_per(1000):
        yield [
            item.normalized_ip,
            item.ip_version,
            item.occurrence_count,
            "是" if item.is_public else "否",
            item.stage,
            item.first_position,
            item.last_position,
        ]


def txt_stream(session, task_id: str, stage: str):
    yield "\t".join(ERROR_HEADERS if stage == "invalid" else HEADERS) + "\n"
    for row in rows_for_stage(session, task_id, stage):
        yield "\t".join("" if value is None else str(value) for value in row) + "\n"


def xlsx_bytes(session, task_id: str, stage: str) -> bytes:
    workbook = Workbook(write_only=True)
    sheet = workbook.create_sheet("XCheck")
    sheet.append(ERROR_HEADERS if stage == "invalid" else HEADERS)
    for row in rows_for_stage(session, task_id, stage):
        sheet.append(row)
    output = io.BytesIO()
    workbook.save(output)
    return output.getvalue()
