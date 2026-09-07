import json
import time
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import AnyHttpUrl, BaseModel, Field

from xcheck.errors import raise_api_problem
from xcheck.models import Setting
from xcheck.services.threatbook import ThreatBookClient
from xcheck.services.whitelist import WhitelistClient

router = APIRouter(prefix="/api/settings", tags=["settings"])

_EMPTY_TEST_SUMMARY = {
    "status": "untested",
    "tested_at": None,
    "latency_ms": None,
    "error_code": None,
    "fallback": None,
}


class SettingsUpdate(BaseModel):
    whitelist_api_url: AnyHttpUrl | None = None
    threatbook_api_url: AnyHttpUrl | None = None
    threatbook_api_key: str | None = Field(default=None, max_length=512)
    clear_threatbook_api_key: bool = False
    threatbook_batch_size: int | None = Field(default=None, ge=1, le=100)
    threatbook_safe_ips_per_minute: int | None = Field(default=None, ge=1, le=1000)
    threatbook_daily_budget: int | None = Field(default=None, ge=1)
    threatbook_max_retries: int | None = Field(default=None, ge=0, le=3)
    ui_language: Literal["en-US", "zh-CN"] | None = None
    theme_id: Literal[
        "threatbook-red",
        "intelligence-blue",
        "eye-care",
        "midnight-violet",
        "amber-sand",
        "ocean-mist",
    ] | None = None
    homepage_mode: Literal["overview", "landscape", "operations"] | None = None
    motion_intensity: Literal["off", "subtle", "medium", "strong"] | None = None


def _safe_test_summary(raw_value: str) -> dict:
    try:
        value = json.loads(raw_value)
    except (TypeError, json.JSONDecodeError):
        return dict(_EMPTY_TEST_SUMMARY)
    if not isinstance(value, dict) or value.get("status") not in {"success", "failed"}:
        return dict(_EMPTY_TEST_SUMMARY)

    def bounded_text(field: str, limit: int) -> str | None:
        candidate = value.get(field)
        return candidate[:limit] if isinstance(candidate, str) else None

    latency_ms = value.get("latency_ms")
    return {
        "status": value["status"],
        "tested_at": bounded_text("tested_at", 64),
        "latency_ms": latency_ms
        if isinstance(latency_ms, int) and 0 <= latency_ms <= 3_600_000
        else None,
        "error_code": bounded_text("error_code", 128),
        "fallback": bounded_text("fallback", 240),
    }


def _payload(settings) -> dict:
    return {
        "whitelist_api_url": settings.whitelist_api_url,
        "threatbook_api_url": settings.threatbook_api_url,
        "upload_max_bytes": settings.upload_max_bytes,
        "threatbook_batch_size": settings.threatbook_batch_size,
        "threatbook_safe_ips_per_minute": settings.threatbook_safe_ips_per_minute,
        "threatbook_daily_budget": settings.threatbook_daily_budget,
        "threatbook_max_retries": settings.threatbook_max_retries,
        "threatbook_api_key_configured": bool(settings.threatbook_api_key),
        "ui_language": settings.ui_language,
        "theme_id": settings.theme_id,
        "homepage_mode": settings.homepage_mode,
        "motion_intensity": settings.motion_intensity,
        "integration_tests": {
            "whitelist": _safe_test_summary(settings.whitelist_test_summary),
            "threatbook": _safe_test_summary(settings.threatbook_test_summary),
        },
    }


def _save_test_summary(
    request: Request,
    integration: Literal["whitelist", "threatbook"],
    *,
    status: Literal["success", "failed"],
    latency_ms: int,
    error_code: str | None = None,
    fallback: str | None = None,
) -> None:
    summary = json.dumps(
        {
            "status": status,
            "tested_at": datetime.now(UTC).isoformat(),
            "latency_ms": max(0, latency_ms),
            "error_code": error_code,
            "fallback": fallback,
        },
        separators=(",", ":"),
    )
    key = f"{integration}_test_summary"
    with request.app.state.settings_lock:
        with request.app.state.session_factory() as session:
            setting = session.get(Setting, key)
            if setting is None:
                session.add(Setting(key=key, value=summary))
            else:
                setting.value = summary
            session.commit()
        new_settings = request.app.state.settings.model_copy(update={key: summary}, deep=True)
        request.app.state.settings = new_settings
        request.app.state.worker.apply_runtime_settings(new_settings)


@router.get("")
def get_system_settings(request: Request):
    return _payload(request.app.state.settings)


@router.put("")
def update_system_settings(payload: SettingsUpdate, request: Request):
    with request.app.state.settings_lock:
        settings = request.app.state.settings
        updates = payload.model_dump(exclude_unset=True)
        clear_key = updates.pop("clear_threatbook_api_key", False)
        proposed_key = updates.pop("threatbook_api_key", None)
        proposed_url = updates.get("threatbook_api_url")
        url_changed = proposed_url is not None and str(proposed_url) != settings.threatbook_api_url
        if clear_key:
            updates["threatbook_api_key"] = ""
        elif proposed_key:
            updates["threatbook_api_key"] = proposed_key
        elif url_changed:
            updates["threatbook_api_key"] = ""

        normalized_updates = {
            key: str(value) if isinstance(value, AnyHttpUrl) else value
            for key, value in updates.items()
            if value is not None
        }
        with request.app.state.session_factory() as session:
            for key, value in normalized_updates.items():
                setting = session.get(Setting, key)
                if setting is None:
                    setting = Setting(key=key, value=str(value))
                    session.add(setting)
                else:
                    setting.value = str(value)
            session.commit()

        new_settings = settings.model_copy(update=normalized_updates, deep=True)
        request.app.state.settings = new_settings
        request.app.state.worker.apply_runtime_settings(new_settings)
    return _payload(new_settings)


@router.post("/test-whitelist")
def test_whitelist_connection(request: Request):
    with request.app.state.settings_lock:
        settings = request.app.state.settings.model_copy(deep=True)
    started = time.perf_counter()
    try:
        payload = WhitelistClient(settings.whitelist_api_url).query(["8.8.8.8"])
        result = next(
            (item for item in payload["results"] if item.get("query") == "8.8.8.8"),
            None,
        )
        result_code = result.get("result_code") if result else None
        if result_code not in {"active", "reference", "inactive", "not_found", "invalid"}:
            raise ValueError("invalid response")
    except Exception as exc:
        latency_ms = round((time.perf_counter() - started) * 1000)
        code = (
            "integration.whitelist.invalid_response"
            if isinstance(exc, ValueError)
            else "integration.whitelist.test_failed"
        )
        fallback = (
            "The whitelist API returned an invalid response."
            if isinstance(exc, ValueError)
            else "Whitelist API connection test failed."
        )
        _save_test_summary(
            request,
            "whitelist",
            status="failed",
            latency_ms=latency_ms,
            error_code=code,
            fallback=fallback,
        )
        raise_api_problem(502, code, fallback)
    latency_ms = round((time.perf_counter() - started) * 1000)
    _save_test_summary(request, "whitelist", status="success", latency_ms=latency_ms)
    return {
        "ok": True,
        "code": "integration.whitelist.test_succeeded",
        "fallback": "Whitelist API is available.",
        "params": {"result_code": result_code},
        "latency_ms": latency_ms,
    }


@router.post("/test-threatbook")
def test_threatbook_connection(request: Request):
    with request.app.state.settings_lock:
        settings = request.app.state.settings.model_copy(deep=True)
    if not settings.threatbook_api_key:
        fallback = "Save the ThreatBook API key before testing the integration."
        _save_test_summary(
            request,
            "threatbook",
            status="failed",
            latency_ms=0,
            error_code="integration.threatbook.api_key_required",
            fallback=fallback,
        )
        raise_api_problem(409, "integration.threatbook.api_key_required", fallback)
    started = time.perf_counter()
    try:
        payload = ThreatBookClient(
            settings.threatbook_api_url,
            settings.threatbook_api_key,
        ).query(["8.8.8.8"])
        response_code = int(payload.get("response_code", -999))
        if response_code < 0:
            raise RuntimeError(payload.get("verbose_msg") or f"微步错误码 {response_code}")
    except Exception:
        latency_ms = round((time.perf_counter() - started) * 1000)
        code = "integration.threatbook.test_failed"
        fallback = "ThreatBook API authentication test failed."
        _save_test_summary(
            request,
            "threatbook",
            status="failed",
            latency_ms=latency_ms,
            error_code=code,
            fallback=fallback,
        )
        raise_api_problem(502, code, fallback)
    latency_ms = round((time.perf_counter() - started) * 1000)
    _save_test_summary(request, "threatbook", status="success", latency_ms=latency_ms)
    return {
        "ok": True,
        "code": "integration.threatbook.test_succeeded",
        "fallback": "ThreatBook API authentication succeeded.",
        "params": {},
        "latency_ms": latency_ms,
    }
