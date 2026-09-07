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


EXPORT_TEXT = {
    "en-US": {
        "sheet": "XCheck Export",
        "headers": [
            "IP",
            "IP Version",
            "Occurrences",
            "Public Address",
            "Stage",
            "First Position",
            "Last Position",
        ],
        "error_headers": ["Raw Value", "Source Position", "Error Reason"],
        "yes": "Yes",
        "no": "No",
        "stages": {
            "validated": "Validated",
            "whitelist_removed": "Whitelist Removed",
            "whitelist_clear": "Whitelist Clear",
            "non_public": "Non-public",
            "threatbook_ready": "Ready for ThreatBook",
            "threatbook_complete": "ThreatBook Complete",
            "malicious": "Malicious",
            "high_confidence_malicious": "High-confidence Malicious",
            "non_malicious": "Not Malicious",
            "failed": "Failed",
        },
    },
    "zh-CN": {
        "sheet": "XCheck 导出",
        "headers": ["IP", "IP版本", "出现次数", "是否公网", "阶段", "首次位置", "最后位置"],
        "error_headers": ["原始值", "来源位置", "错误原因"],
        "yes": "是",
        "no": "否",
        "stages": {
            "validated": "已校验",
            "whitelist_removed": "白名单已移除",
            "whitelist_clear": "白名单未命中",
            "non_public": "非公网",
            "threatbook_ready": "微步待查",
            "threatbook_complete": "微步已完成",
            "malicious": "恶意",
            "high_confidence_malicious": "高可信恶意",
            "non_malicious": "非恶意",
            "failed": "失败",
        },
    },
}


def _text(language: str) -> dict:
    return EXPORT_TEXT.get(language, EXPORT_TEXT["en-US"])


def rows_for_stage(
    session,
    task_id: str,
    stage: str,
    language: str = "en-US",
) -> Iterator[list]:
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
    text = _text(language)
    for item in session.scalars(query.order_by(TaskIP.id)).yield_per(1000):
        yield [
            item.normalized_ip,
            item.ip_version,
            item.occurrence_count,
            text["yes"] if item.is_public else text["no"],
            text["stages"].get(item.stage, item.stage),
            item.first_position,
            item.last_position,
        ]


def txt_stream(session, task_id: str, stage: str, language: str = "en-US"):
    text = _text(language)
    headers = text["error_headers"] if stage == "invalid" else text["headers"]
    yield "\t".join(headers) + "\n"
    for row in rows_for_stage(session, task_id, stage, language):
        yield "\t".join("" if value is None else str(value) for value in row) + "\n"


def xlsx_bytes(session, task_id: str, stage: str, language: str = "en-US") -> bytes:
    text = _text(language)
    workbook = Workbook(write_only=True)
    sheet = workbook.create_sheet(text["sheet"])
    sheet.append(text["error_headers"] if stage == "invalid" else text["headers"])
    for row in rows_for_stage(session, task_id, stage, language):
        sheet.append(row)
    output = io.BytesIO()
    workbook.save(output)
    return output.getvalue()
