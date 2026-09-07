import time
from pathlib import Path
from urllib.parse import quote

from fastapi.testclient import TestClient
from xcheck.models import Setting


def _complete_settings(**overrides):
    payload = {
        "whitelist_api_url": "http://whitelist.test/api/query",
        "threatbook_api_url": "https://threatbook.test/ip",
        "threatbook_api_key": "new-secret-key",
        "threatbook_batch_size": 50,
        "threatbook_safe_ips_per_minute": 700,
        "threatbook_daily_budget": 9000,
        "threatbook_max_retries": 2,
    }
    payload.update(overrides)
    return payload


def test_settings_never_return_api_key(client, monkeypatch):
    monkeypatch.setenv("THREATBOOK_API_KEY", "very-secret")
    from xcheck.config import get_settings

    get_settings.cache_clear()
    response = client.get("/api/settings")
    assert response.status_code == 200
    assert response.json()["threatbook_api_key_configured"] is False
    assert "key" not in " ".join(response.json()).lower().replace("api_key_configured", "")


def test_empty_database_returns_default_display_settings(client):
    response = client.get("/api/settings")

    assert response.status_code == 200
    assert {
        key: response.json()[key]
        for key in ("ui_language", "theme_id", "homepage_mode", "motion_intensity")
    } == {
        "ui_language": "en-US",
        "theme_id": "threatbook-red",
        "homepage_mode": "overview",
        "motion_intensity": "medium",
    }


def test_display_settings_persist_across_fresh_app_instances(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'xcheck.db'}")
    from xcheck.config import get_settings
    from xcheck.main import create_app

    get_settings.cache_clear()
    with TestClient(create_app()) as first_client:
        response = first_client.put(
            "/api/settings",
            json={
                "ui_language": "zh-CN",
                "theme_id": "ocean-mist",
                "homepage_mode": "operations",
                "motion_intensity": "strong",
            },
        )
        assert response.status_code == 200

    get_settings.cache_clear()
    with TestClient(create_app()) as second_client:
        saved = second_client.get("/api/settings")

    assert saved.status_code == 200
    assert saved.json()["ui_language"] == "zh-CN"
    assert saved.json()["theme_id"] == "ocean-mist"
    assert saved.json()["homepage_mode"] == "operations"
    assert saved.json()["motion_intensity"] == "strong"
    get_settings.cache_clear()


def test_invalid_display_setting_does_not_change_saved_fields(client):
    initial = client.put(
        "/api/settings",
        json={
            "ui_language": "zh-CN",
            "theme_id": "eye-care",
            "homepage_mode": "landscape",
            "motion_intensity": "subtle",
        },
    )
    assert initial.status_code == 200

    invalid = client.put(
        "/api/settings",
        json={
            "ui_language": "fr-FR",
            "theme_id": "unknown-theme",
            "homepage_mode": "invalid-mode",
            "motion_intensity": "extreme",
        },
    )

    assert invalid.status_code == 422
    saved = client.get("/api/settings").json()
    assert saved["ui_language"] == "zh-CN"
    assert saved["theme_id"] == "eye-care"
    assert saved["homepage_mode"] == "landscape"
    assert saved["motion_intensity"] == "subtle"


def test_invalid_setting_returns_structured_validation_problem(client):
    response = client.put("/api/settings", json={"ui_language": "fr-FR"})

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "request.validation_failed"
    assert response.json()["detail"]["fallback"] == "The request contains invalid values."
    assert response.json()["detail"]["params"]["field"] == "ui_language"


def test_ip_diagnostics_contains_source_and_stage(client):
    task_id = client.post("/api/tasks/manual", json={"text": "8.8.8.8\n8.8.8.8"}).json()["id"]
    deadline = time.monotonic() + 3
    item = None
    while time.monotonic() < deadline:
        payload = client.get(f"/api/tasks/{task_id}/ips").json()
        if payload["items"]:
            item = payload["items"][0]
            break
        time.sleep(0.02)
    response = client.get(f"/api/tasks/{task_id}/ips/{item['id']}")
    assert response.status_code == 200
    assert response.json()["ip"] == "8.8.8.8"
    assert response.json()["occurrence_count"] == 2
    assert response.json()["sample_positions"] == ["item:1", "item:2"]


def test_settings_validate_safe_limits(client):
    response = client.put("/api/settings", json={"threatbook_batch_size": 101})
    assert response.status_code == 422
    response = client.put(
        "/api/settings",
        json={
            "threatbook_batch_size": 50,
            "threatbook_safe_ips_per_minute": 700,
            "threatbook_daily_budget": 9000,
            "threatbook_max_retries": 2,
        },
    )
    assert response.status_code == 200
    assert response.json()["threatbook_batch_size"] == 50


def test_api_urls_and_key_can_be_saved_without_returning_secret(client):
    response = client.put("/api/settings", json=_complete_settings())

    assert response.status_code == 200
    assert response.json()["whitelist_api_url"] == "http://whitelist.test/api/query"
    assert response.json()["threatbook_api_url"] == "https://threatbook.test/ip"
    assert response.json()["threatbook_api_key_configured"] is True
    assert "new-secret-key" not in response.text

    loaded = client.get("/api/settings")
    assert loaded.json()["threatbook_api_key_configured"] is True
    assert "new-secret-key" not in loaded.text


def test_saved_rate_limit_is_applied_to_running_worker(client, app):
    response = client.put("/api/settings", json=_complete_settings(threatbook_safe_ips_per_minute=600))

    assert response.status_code == 200
    assert app.state.worker.limiter.interval_per_ip == 0.1


def test_saving_unchanged_rate_does_not_reset_active_limiter(client, app):
    limiter = app.state.worker.limiter
    response = client.put("/api/settings", json={"whitelist_api_url": "http://new.test/query"})

    assert response.status_code == 200
    assert app.state.worker.limiter is limiter


def test_empty_key_keeps_saved_key_and_explicit_clear_removes_it(client):
    client.put("/api/settings", json=_complete_settings())
    kept = client.put("/api/settings", json=_complete_settings(threatbook_api_key=""))
    assert kept.json()["threatbook_api_key_configured"] is True

    cleared = client.put(
        "/api/settings",
        json=_complete_settings(threatbook_api_key="", clear_threatbook_api_key=True),
    )
    assert cleared.json()["threatbook_api_key_configured"] is False


def test_changing_threatbook_url_without_reentering_key_clears_saved_key(client):
    client.put("/api/settings", json=_complete_settings())
    changed = client.put(
        "/api/settings",
        json={"threatbook_api_url": "https://replacement.test/ip", "threatbook_api_key": ""},
    )

    assert changed.status_code == 200
    assert changed.json()["threatbook_api_url"] == "https://replacement.test/ip"
    assert changed.json()["threatbook_api_key_configured"] is False


def test_setting_update_atomically_swaps_an_immutable_snapshot(client, app):
    client.put("/api/settings", json=_complete_settings())
    previous = app.state.settings
    client.put("/api/settings", json={"threatbook_api_url": "https://replacement.test/ip"})

    assert previous.threatbook_api_url == "https://threatbook.test/ip"
    assert previous.threatbook_api_key == "new-secret-key"
    assert app.state.settings is not previous
    assert app.state.worker.settings is app.state.settings
    assert app.state.settings.threatbook_api_key == ""


def test_whitelist_authentication_probe_uses_saved_url(client, monkeypatch):
    captured = {}

    class FakeWhitelistClient:
        def __init__(self, url):
            captured["url"] = url

        def query(self, addresses):
            captured["addresses"] = addresses
            return {"request_id": "probe", "results": [{"query": "8.8.8.8", "result_code": "not_found"}]}

    monkeypatch.setattr("xcheck.api.settings.WhitelistClient", FakeWhitelistClient)
    client.put("/api/settings", json=_complete_settings())
    response = client.post("/api/settings/test-whitelist")

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert captured == {"url": "http://whitelist.test/api/query", "addresses": ["8.8.8.8"]}


def test_whitelist_probe_persists_only_a_safe_success_summary(client, app, monkeypatch):
    class FakeWhitelistClient:
        def __init__(self, _url):
            pass

        def query(self, _addresses):
            return {
                "request_id": "private-response-id",
                "results": [{"query": "8.8.8.8", "result_code": "not_found"}],
            }

    monkeypatch.setattr("xcheck.api.settings.WhitelistClient", FakeWhitelistClient)
    response = client.post("/api/settings/test-whitelist")

    assert response.status_code == 200
    summary = client.get("/api/settings").json()["integration_tests"]["whitelist"]
    assert summary["status"] == "success"
    assert summary["tested_at"]
    assert isinstance(summary["latency_ms"], int)
    assert summary["error_code"] is None
    assert summary["fallback"] is None
    with app.state.session_factory() as session:
        stored = session.get(Setting, "whitelist_test_summary").value
    assert "8.8.8.8" not in stored
    assert "private-response-id" not in stored


def test_whitelist_probe_rejects_result_without_matching_verdict(client, monkeypatch):
    class MalformedWhitelistClient:
        def __init__(self, _url):
            pass

        def query(self, _addresses):
            return {"request_id": "probe", "results": [{}]}

    monkeypatch.setattr("xcheck.api.settings.WhitelistClient", MalformedWhitelistClient)
    response = client.post("/api/settings/test-whitelist")

    assert response.status_code == 502
    assert response.json()["detail"]["code"] == "integration.whitelist.invalid_response"


def test_threatbook_authentication_probe_is_safe(client, monkeypatch):
    captured = {}

    class FakeThreatBookClient:
        def __init__(self, url, api_key):
            captured.update(url=url, api_key=api_key)

        def query(self, addresses):
            captured["addresses"] = addresses
            return {"response_code": 0, "verbose_msg": "Ok", "data": {"8.8.8.8": {}}}

    monkeypatch.setattr("xcheck.api.settings.ThreatBookClient", FakeThreatBookClient)
    client.put("/api/settings", json=_complete_settings())
    response = client.post("/api/settings/test-threatbook")

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert captured == {
        "url": "https://threatbook.test/ip",
        "api_key": "new-secret-key",
        "addresses": ["8.8.8.8"],
    }
    assert "new-secret-key" not in response.text


def test_probe_failure_never_leaks_api_key(client, monkeypatch):
    class FailingThreatBookClient:
        def __init__(self, _url, api_key):
            self.api_key = api_key

        def query(self, _addresses):
            raise RuntimeError(f"authentication failed for {self.api_key}")

    monkeypatch.setattr("xcheck.api.settings.ThreatBookClient", FailingThreatBookClient)
    client.put("/api/settings", json=_complete_settings())
    response = client.post("/api/settings/test-threatbook")

    assert response.status_code == 502
    assert "new-secret-key" not in response.text
    assert response.json()["detail"]["code"] == "integration.threatbook.test_failed"


def test_failed_threatbook_probe_persists_safe_structured_problem(client, app, monkeypatch):
    class FailingThreatBookClient:
        def __init__(self, _url, _api_key):
            pass

        def query(self, _addresses):
            raise RuntimeError("private upstream body for 8.8.8.8 and new-secret-key")

    monkeypatch.setattr("xcheck.api.settings.ThreatBookClient", FailingThreatBookClient)
    client.put("/api/settings", json=_complete_settings())
    response = client.post("/api/settings/test-threatbook")

    assert response.status_code == 502
    assert response.json()["detail"] == {
        "code": "integration.threatbook.test_failed",
        "fallback": "ThreatBook API authentication test failed.",
        "params": {},
    }
    summary = client.get("/api/settings").json()["integration_tests"]["threatbook"]
    assert summary["status"] == "failed"
    assert summary["error_code"] == "integration.threatbook.test_failed"
    assert summary["fallback"] == "ThreatBook API authentication test failed."
    with app.state.session_factory() as session:
        stored = session.get(Setting, "threatbook_test_summary").value
    assert "8.8.8.8" not in stored
    assert "new-secret-key" not in stored
    assert "private upstream body" not in stored


def test_probe_failure_redacts_percent_encoded_api_key(client, monkeypatch):
    secret = "secret+/= value"
    encoded = quote(secret, safe="")

    class FailingThreatBookClient:
        def __init__(self, _url, _api_key):
            pass

        def query(self, _addresses):
            raise RuntimeError(f"request failed: https://example.test/?apikey={encoded}")

    monkeypatch.setattr("xcheck.api.settings.ThreatBookClient", FailingThreatBookClient)
    client.put("/api/settings", json=_complete_settings(threatbook_api_key=secret))
    response = client.post("/api/settings/test-threatbook")

    assert response.status_code == 502
    assert secret not in response.text
    assert encoded not in response.text
