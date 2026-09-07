import time
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import AnyHttpUrl, BaseModel, Field

from xcheck.models import Setting
from xcheck.services.threatbook import ThreatBookClient, safe_integration_error
from xcheck.services.whitelist import WhitelistClient

router = APIRouter(prefix="/api/settings", tags=["settings"])


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
    }


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
            raise ValueError("白名单API返回结构不正确")
    except Exception as exc:
        raise HTTPException(502, f"白名单接口测试失败：{safe_integration_error(exc)}") from exc
    return {
        "ok": True,
        "message": f"白名单接口可用，测试结果：{result_code}",
        "latency_ms": round((time.perf_counter() - started) * 1000),
    }


@router.post("/test-threatbook")
def test_threatbook_connection(request: Request):
    with request.app.state.settings_lock:
        settings = request.app.state.settings.model_copy(deep=True)
    if not settings.threatbook_api_key:
        raise HTTPException(409, "请先保存微步 API Key")
    started = time.perf_counter()
    try:
        payload = ThreatBookClient(
            settings.threatbook_api_url,
            settings.threatbook_api_key,
        ).query(["8.8.8.8"])
        response_code = int(payload.get("response_code", -999))
        if response_code < 0:
            raise RuntimeError(payload.get("verbose_msg") or f"微步错误码 {response_code}")
    except Exception as exc:
        safe_message = safe_integration_error(exc, settings.threatbook_api_key)
        raise HTTPException(502, f"微步认证测试失败：{safe_message}") from exc
    return {
        "ok": True,
        "message": "微步接口与 API Key 认证成功",
        "latency_ms": round((time.perf_counter() - started) * 1000),
    }
