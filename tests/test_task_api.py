import json
import time
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from xcheck.models import (
    StepAttempt,
    StepStatus,
    Task,
    TaskIP,
    TaskStatus,
    TaskStep,
    ThreatbookBatch,
    ThreatbookResult,
)
from xcheck.services.pipeline import create_manual_task, ingest_task
from xcheck.services.whitelist import run_whitelist


def test_task_detail_exposes_only_allowlisted_threatbook_config(client, app):
    """Fails if persisted execution settings are hidden or raw secrets leak."""
    task_id = create_manual_task(app.state.session_factory, "8.8.8.8", app.state.settings)
    with app.state.session_factory() as session:
        task = session.get(Task, task_id)
        task.config_snapshot = json.dumps(
            {
                "batch_size": 64,
                "safe_ips_per_minute": 720,
                "daily_budget": 9000,
                "max_retries": 3,
                "api_key": "must-not-leak",
                "url": "https://secret.example.test/query",
            }
        )
        session.commit()

    payload = client.get(f"/api/tasks/{task_id}").json()

    assert payload["threatbook_config"] == {
        "batch_size": 64,
        "safe_ips_per_minute": 720,
        "daily_budget": 9000,
        "max_retries": 3,
    }
    assert "config_snapshot" not in payload
    assert "must-not-leak" not in json.dumps(payload)
    assert "secret.example.test" not in json.dumps(payload)


def test_task_detail_tolerates_invalid_config_snapshot(client, app):
    """Fails if historic malformed snapshots break task detail loading."""
    task_id = create_manual_task(app.state.session_factory, "1.1.1.1", app.state.settings)
    with app.state.session_factory() as session:
        task = session.get(Task, task_id)
        task.config_snapshot = "not-json"
        session.commit()

    response = client.get(f"/api/tasks/{task_id}")

    assert response.status_code == 200
    assert response.json()["threatbook_config"] == {
        "batch_size": None,
        "safe_ips_per_minute": None,
        "daily_budget": None,
        "max_retries": None,
    }


def test_task_detail_rejects_out_of_range_threatbook_config(client, app):
    """Fails if historic snapshots can bypass the runtime settings bounds."""
    task_id = create_manual_task(app.state.session_factory, "9.9.9.9", app.state.settings)
    with app.state.session_factory() as session:
        task = session.get(Task, task_id)
        task.config_snapshot = json.dumps(
            {
                "batch_size": 0,
                "safe_ips_per_minute": 1001,
                "daily_budget": 0,
                "max_retries": 4,
            }
        )
        session.commit()

    payload = client.get(f"/api/tasks/{task_id}").json()

    assert payload["threatbook_config"] == {
        "batch_size": None,
        "safe_ips_per_minute": None,
        "daily_budget": None,
        "max_retries": None,
    }


def test_task_diagnostics_are_bounded_and_never_return_unresolved_ip_arrays(client, app):
    """Fails if diagnostics can materialize an entire large task in one response."""
    task_id = create_manual_task(app.state.session_factory, "8.8.8.8", app.state.settings)
    with app.state.session_factory() as session:
        task = session.get(Task, task_id)
        task.status = TaskStatus.FAILED.value
        task.current_step = "threatbook_query"
        for index in range(1, 4):
            batch_id = f"bounded-batch-{index}"
            session.add(
                ThreatbookBatch(
                    id=batch_id,
                    task_id=task_id,
                    batch_number=index,
                    status="failed",
                    addresses_json=json.dumps([f"8.8.8.{index}"]),
                    unresolved_json=json.dumps([f"8.8.8.{index}"]),
                    attempt_count=1,
                    response_code=-1,
                    response_message="failure must-not-leak",
                )
            )
            session.add(
                StepAttempt(
                    task_id=task_id,
                    step_name="threatbook_query",
                    batch_id=batch_id,
                    attempt_number=1,
                    status="failed",
                    safe_request_json='{"api_key":"must-not-leak","resource_count":1}',
                    error_type="RuntimeError",
                    error_message="safe failure",
                )
            )
        session.commit()

    response = client.get(f"/api/tasks/{task_id}/diagnostics?attempt_limit=2&batch_limit=2")

    assert response.status_code == 200
    payload = response.json()
    assert payload["attempt_total"] == 3
    assert payload["batch_total"] == 3
    assert payload["attempt_limit"] == 2
    assert payload["batch_limit"] == 2
    assert len(payload["attempts"]) == 2
    assert len(payload["batches"]) == 2
    assert all(batch["unresolved_count"] == 1 for batch in payload["batches"])
    assert all("unresolved" not in batch for batch in payload["batches"])
    assert "must-not-leak" not in response.text
    assert "8.8.8." not in response.text
    assert client.get(f"/api/tasks/{task_id}/diagnostics?attempt_limit=201").status_code == 422


def test_manual_task_reaches_whitelist_confirmation(client):
    response = client.post("/api/tasks/manual", json={"text": "8.8.8.8\n8.8.8.8\n错误地址"})
    assert response.status_code == 202
    task_id = response.json()["id"]

    deadline = time.monotonic() + 3
    task = {}
    while time.monotonic() < deadline:
        task = client.get(f"/api/tasks/{task_id}").json()
        if task["status"] != "queued" and task["status"] != "running":
            break
        time.sleep(0.02)

    assert task["raw_count"] == 3
    assert task["unique_count"] == 1
    assert task["status"] in {"waiting_whitelist_confirmation", "failed"}


def test_history_is_server_paginated(client):
    for index in range(3):
        client.post("/api/tasks/manual", json={"text": f"8.8.8.{index + 1}"})
    response = client.get("/api/tasks?page=1&page_size=2")
    assert response.status_code == 200
    assert response.json()["total"] == 3
    assert len(response.json()["items"]) == 2


def test_start_threatbook_requires_backend_api_key(client):
    task_id = client.post("/api/tasks/manual", json={"text": "8.8.8.8"}).json()["id"]
    response = client.post(f"/api/tasks/{task_id}/actions/start-threatbook")
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "integration.threatbook.api_key_required"


def test_start_and_retry_failures_return_structured_problems(client):
    missing = client.get("/api/tasks/does-not-exist")
    start = client.post("/api/tasks/does-not-exist/actions/start-threatbook")
    retry = client.post("/api/tasks/does-not-exist/steps/threatbook_query/retry")

    assert missing.status_code == 404
    assert missing.json()["detail"] == {
        "code": "task.not_found",
        "fallback": "The task does not exist.",
        "params": {"task_id": "does-not-exist"},
    }
    assert start.status_code == 409
    assert start.json()["detail"]["code"] == "integration.threatbook.api_key_required"
    assert retry.status_code == 404
    assert retry.json()["detail"]["code"] == "task.not_found"


def test_uploaded_original_file_can_be_downloaded(client):
    response = client.post(
        "/api/tasks/upload?input_type=csv",
        files={"file": ("访问日志.csv", "访问源 IP,时间\n8.8.8.8,t\n".encode(), "text/csv")},
    )
    assert response.status_code == 202
    task_id = response.json()["id"]
    download = client.get(f"/api/tasks/{task_id}/original")
    assert download.status_code == 200
    assert "8.8.8.8" in download.content.decode()


def test_both_log_types_accept_tabular_extensions_without_cross_type_rejection(client):
    attack = client.post(
        "/api/tasks/upload?input_type=attack",
        files={"file": ("攻击日志.csv", b"srcAddress,event\n8.8.8.8,scan\n", "text/csv")},
    )
    access = client.post(
        "/api/tasks/upload?input_type=access",
        files={"file": ("访问日志.csv", "访问源 IP,时间\n1.1.1.1,now\n".encode(), "text/csv")},
    )

    assert attack.status_code == 202
    assert attack.json()["input_type"] == "attack"
    assert access.status_code == 202
    assert access.json()["input_type"] == "access"


def test_zero_hit_whitelist_run_auto_advances_but_hit_run_waits_for_confirmation(app):
    """Fails if clear tasks still need removal confirmation or hits are auto-removed."""
    factory = app.state.session_factory
    clear_task_id = create_manual_task(factory, "8.8.8.8", app.state.settings)
    hit_task_id = create_manual_task(factory, "1.1.1.1", app.state.settings)
    ingest_task(factory, clear_task_id, app.state.settings)
    ingest_task(factory, hit_task_id, app.state.settings)

    class WhitelistClient:
        def query(self, addresses):
            return {
                "request_id": "req-transition",
                "results": [
                    {
                        "query": address,
                        "result_code": "active" if address == "1.1.1.1" else "not_found",
                        "verdict": "matched" if address == "1.1.1.1" else "clear",
                        "matches": [],
                    }
                    for address in addresses
                ],
            }

    run_whitelist(factory, clear_task_id, WhitelistClient())
    run_whitelist(factory, hit_task_id, WhitelistClient())

    with factory() as session:
        clear_task = session.get(Task, clear_task_id)
        hit_task = session.get(Task, hit_task_id)
        clear_ip = session.scalar(select(TaskIP).where(TaskIP.task_id == clear_task_id))
        hit_ip = session.scalar(select(TaskIP).where(TaskIP.task_id == hit_task_id))
        assert clear_task.status == TaskStatus.WAITING_THREATBOOK.value
        assert clear_task.current_step == "filter_non_public"
        assert clear_ip.stage == "threatbook_ready"
        assert hit_task.status == TaskStatus.WAITING_WHITELIST.value
        assert hit_ip.stage == "whitelist_hit"


@pytest.mark.parametrize(
    "initial_status", [TaskStatus.WAITING_THREATBOOK.value, TaskStatus.PAUSED_QUOTA.value]
)
def test_start_threatbook_atomically_claims_delayed_work_and_rejects_duplicates(
    app, client, monkeypatch, initial_status
):
    """Fails if start/resume returns before a durable queued claim or can enqueue twice."""
    app.state.settings.threatbook_api_key = "configured"
    task_id = create_manual_task(app.state.session_factory, "8.8.8.8", app.state.settings)
    submitted = []
    monkeypatch.setattr(app.state.worker, "submit_threatbook", submitted.append)
    with app.state.session_factory() as session:
        task = session.get(Task, task_id)
        task.status = initial_status
        task.current_step = "filter_non_public"
        session.commit()

    claimed = client.post(f"/api/tasks/{task_id}/actions/start-threatbook")
    duplicate = client.post(f"/api/tasks/{task_id}/actions/start-threatbook")

    assert claimed.status_code == 202
    assert claimed.json()["status"] == TaskStatus.QUEUED.value
    assert claimed.json()["current_step"] == "threatbook_query"
    persisted = client.get(f"/api/tasks/{task_id}").json()
    assert persisted["status"] == TaskStatus.QUEUED.value
    assert persisted["current_step"] == "threatbook_query"
    assert duplicate.status_code == 409
    assert submitted == [task_id]

    recovered = []
    misrouted_to_ingest = []
    monkeypatch.setattr(app.state.worker, "submit_threatbook", recovered.append)
    monkeypatch.setattr(app.state.worker, "submit_ingest", misrouted_to_ingest.append)
    app.state.worker.recover()

    assert recovered == [task_id]
    assert misrouted_to_ingest == []


def test_threatbook_retry_atomically_claims_work_and_rejects_duplicates(app, client, monkeypatch):
    """Fails if two retry requests can enqueue the same failed ThreatBook step."""
    app.state.settings.threatbook_api_key = "configured"
    task_id = create_manual_task(app.state.session_factory, "8.8.8.8", app.state.settings)
    submitted = []
    monkeypatch.setattr(app.state.worker, "submit_threatbook", submitted.append)
    with app.state.session_factory() as session:
        task = session.get(Task, task_id)
        task.status = TaskStatus.FAILED.value
        task.current_step = "archive_results"
        step = session.scalar(
            select(TaskStep).where(TaskStep.task_id == task_id, TaskStep.name == "threatbook_query")
        )
        step.status = StepStatus.FAILED.value
        session.commit()

    claimed = client.post(f"/api/tasks/{task_id}/steps/threatbook_query/retry")
    duplicate = client.post(f"/api/tasks/{task_id}/steps/threatbook_query/retry")

    assert claimed.status_code == 202
    assert claimed.json()["status"] == TaskStatus.QUEUED.value
    assert claimed.json()["current_step"] == "threatbook_query"
    assert duplicate.status_code == 409
    assert submitted == [task_id]


def test_task_detail_exposes_persisted_step_timestamps(app, client):
    """Fails if elapsed time cannot be derived from persisted execution timestamps."""
    task_id = create_manual_task(app.state.session_factory, "8.8.8.8", app.state.settings)
    started = datetime(2026, 8, 14, 1, 2, 3, tzinfo=UTC)
    finished = datetime(2026, 8, 14, 1, 4, 8, tzinfo=UTC)
    with app.state.session_factory() as session:
        step = session.scalar(
            select(TaskStep).where(TaskStep.task_id == task_id, TaskStep.name == "threatbook_query")
        )
        step.started_at = started
        step.finished_at = finished
        session.commit()

    step_payload = next(
        item
        for item in client.get(f"/api/tasks/{task_id}").json()["steps"]
        if item["name"] == "threatbook_query"
    )

    assert step_payload["started_at"] == "2026-08-14T01:02:03"
    assert step_payload["finished_at"] == "2026-08-14T01:04:08"


def test_ip_diagnostics_only_return_allowlisted_threatbook_fields_for_legacy_raw_rows(app, client):
    """Fails if arbitrary legacy raw keys or secret-bearing strings reach per-IP diagnostics."""
    task_id = create_manual_task(app.state.session_factory, "8.8.8.8", app.state.settings)
    ingest_task(app.state.session_factory, task_id, app.state.settings)
    with app.state.session_factory() as session:
        task_ip = session.scalar(select(TaskIP).where(TaskIP.task_id == task_id))
        batch = ThreatbookBatch(
            id="legacy-raw-batch",
            task_id=task_id,
            batch_number=1,
            status="completed",
            addresses_json='["8.8.8.8"]',
        )
        session.add(batch)
        session.add(
            ThreatbookResult(
                task_ip_id=task_ip.id,
                batch_id=batch.id,
                is_malicious=True,
                confidence_level="high",
                severity="critical",
                judgments_json='["botnet"]',
                country="中国",
                province="北京",
                city="北京市",
                carrier="运营商",
                asn_number=64500,
                asn_name="测试 ASN",
                scene="恶意软件",
                update_time="2026-08-14 09:00:00",
                permalink="https://example.test/ip/8.8.8.8",
                raw_json=json.dumps(
                    {
                        "arbitrary_secret": "Bearer legacy-super-secret",
                        "nested": {"not_a_known_key": "token=legacy-super-secret"},
                    }
                ),
            )
        )
        session.commit()
        ip_id = task_ip.id

    response = client.get(f"/api/tasks/{task_id}/ips/{ip_id}")

    assert response.status_code == 200
    assert response.json()["threatbook"] == {
        "batch_id": "legacy-raw-batch",
        "is_malicious": True,
        "confidence_level": "high",
        "severity": "critical",
        "judgments": ["botnet"],
        "country": "中国",
        "province": "北京",
        "city": "北京市",
        "carrier": "运营商",
        "asn_number": 64500,
        "asn_name": "测试 ASN",
        "scene": "恶意软件",
        "update_time": "2026-08-14 09:00:00",
        "permalink": "https://example.test/ip/8.8.8.8",
    }
    assert "legacy-super-secret" not in response.text
    assert "raw" not in response.json()["threatbook"]


@pytest.mark.parametrize("result_code", ["invalid", "unknown_verdict"])
def test_abnormal_zero_hit_whitelist_verdict_fails_instead_of_auto_advancing(app, result_code):
    """Fails if an invalid or unknown zero-hit verdict is treated as a successful clear result."""
    factory = app.state.session_factory
    task_id = create_manual_task(factory, "8.8.8.8", app.state.settings)
    ingest_task(factory, task_id, app.state.settings)

    class AbnormalClient:
        def query(self, addresses):
            return {
                "request_id": "req-abnormal",
                "results": [
                    {
                        "query": address,
                        "result_code": result_code,
                        "verdict": "unexpected",
                        "matches": [],
                    }
                    for address in addresses
                ],
            }

    run_whitelist(factory, task_id, AbnormalClient())

    with factory() as session:
        task = session.get(Task, task_id)
        task_ip = session.scalar(select(TaskIP).where(TaskIP.task_id == task_id))
        step = session.scalar(
            select(TaskStep).where(TaskStep.task_id == task_id, TaskStep.name == "whitelist_query")
        )
        assert task.status == TaskStatus.FAILED.value
        assert task.current_step == "whitelist_query"
        assert task_ip.stage == "invalid"
        assert step.status == StepStatus.FAILED.value
        assert step.finished_at is not None
        assert "异常结论" in task.error_summary
