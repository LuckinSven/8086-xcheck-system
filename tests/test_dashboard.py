import json
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import event
from xcheck.models import (
    DailyUsage,
    Task,
    TaskIP,
    TaskStep,
    ThreatbookBatch,
    ThreatbookResult,
)


def _add_task(
    session,
    task_id: str,
    *,
    status: str,
    created_at: datetime,
    unique_count: int = 0,
    malicious_count: int = 0,
):
    session.add(
        Task(
            id=task_id,
            status=status,
            input_type="manual",
            manual_text="8.8.8.8",
            current_step="threatbook_query",
            unique_count=unique_count,
            threatbook_ready_count=unique_count,
            malicious_count=malicious_count,
            failed_count=1 if status in {"failed", "partial_success"} else 0,
            created_at=created_at,
            updated_at=created_at,
        )
    )
    session.add(
        TaskStep(
            task_id=task_id,
            name="threatbook_query",
            status="failed" if status == "failed" else "running",
            progress_current=4,
            progress_total=10,
            error_summary="safe failure" if status == "failed" else None,
            started_at=created_at,
        )
    )
    session.add(
        ThreatbookBatch(
            id=f"batch-{task_id}",
            task_id=task_id,
            batch_number=1,
            status="completed",
            addresses_json="[]",
            unresolved_json="[]",
        )
    )


def _add_result(
    session,
    task_id: str,
    index: int,
    *,
    country: str,
    province: str,
    severity: str,
    labels: list[str],
):
    item = TaskIP(
        task_id=task_id,
        raw_value=f"8.8.8.{index}",
        normalized_ip=f"8.8.8.{index}",
        ip_version=4,
        is_public=True,
        stage="threatbook_complete",
    )
    session.add(item)
    session.flush()
    session.add(
        ThreatbookResult(
            task_ip_id=item.id,
            batch_id=f"batch-{task_id}",
            is_malicious=True,
            confidence_level="high",
            severity=severity,
            judgments_json=json.dumps(labels),
            country=country,
            province=province,
            city="City",
            raw_json='{"api_key":"must-not-leak","body":"private"}',
        )
    )


def _seed_dashboard(app):
    now = datetime.now(UTC).replace(tzinfo=None)
    with app.state.session_factory() as session:
        _add_task(
            session,
            "risk-task",
            status="running",
            created_at=now - timedelta(hours=2),
            unique_count=10,
            malicious_count=2,
        )
        _add_result(
            session,
            "risk-task",
            1,
            country="China",
            province="Beijing",
            severity="critical",
            labels=["botnet", "scanner"],
        )
        _add_result(
            session,
            "risk-task",
            2,
            country="China",
            province="Sichuan",
            severity="high",
            labels=["scanner"],
        )
        _add_task(
            session,
            "failed-task",
            status="failed",
            created_at=now - timedelta(days=2),
            unique_count=5,
        )
        session.add(DailyUsage(usage_date=date.today(), successful_ips=125))
        session.commit()


def test_empty_dashboard_modes_have_stable_bounded_shapes(client):
    for mode in ("overview", "landscape", "operations"):
        response = client.get("/api/dashboard", params={"mode": mode})

        assert response.status_code == 200
        payload = response.json()
        assert payload["mode"] == mode
        assert payload["generated_at"]
        assert isinstance(payload["summary"], dict)
        assert isinstance(payload["sections"], dict)
        assert all(section["available"] is True for section in payload["sections"].values())

    invalid = client.get("/api/dashboard", params={"mode": "unknown"})
    assert invalid.status_code == 422
    assert invalid.json()["detail"]["code"] == "request.validation_failed"


def test_overview_returns_totals_trend_attention_and_recent_risks(app, client):
    _seed_dashboard(app)

    payload = client.get("/api/dashboard?mode=overview").json()

    assert payload["summary"] == {
        "total_tasks": 2,
        "total_unique_ips": 15,
        "malicious_ips": 2,
        "active_tasks": 1,
        "failed_tasks": 1,
    }
    assert len(payload["sections"]["trend"]["items"]) == 7
    assert payload["sections"]["recent_risks"]["items"][0]["task_id"] == "risk-task"
    assert payload["sections"]["recent_risks"]["items"][0]["labels"] == ["botnet", "scanner"]
    assert payload["sections"]["attention"]["items"][0]["task_id"] == "failed-task"


def test_landscape_returns_last_day_rankings_and_distributions(app, client):
    _seed_dashboard(app)

    payload = client.get("/api/dashboard?mode=landscape").json()

    assert payload["summary"]["malicious_last_24h"] == 2
    assert payload["sections"]["countries"]["items"][0] == {"name": "China", "count": 2}
    assert payload["sections"]["regions"]["items"][0]["count"] == 1
    assert payload["sections"]["labels"]["items"][0] == {"name": "scanner", "count": 2}
    assert payload["sections"]["severities"]["items"] == [
        {"name": "critical", "count": 1},
        {"name": "high", "count": 1},
    ]
    assert len(payload["sections"]["trend"]["items"]) == 7


def test_operations_returns_backlog_progress_budget_and_safe_health(app, client):
    _seed_dashboard(app)

    payload = client.get("/api/dashboard?mode=operations").json()

    assert payload["summary"]["status_counts"]["running"] == 1
    assert payload["summary"]["status_counts"]["failed"] == 1
    assert payload["summary"]["backlog"] == 1
    assert payload["summary"]["progress"] == {"current": 4, "total": 10, "percent": 40}
    assert payload["summary"]["daily_usage"] == 125
    assert payload["summary"]["daily_remaining"] == 9875
    assert payload["summary"]["worker_status"] == "ready"
    assert payload["summary"]["database_status"] == "ready"
    assert payload["sections"]["failed_nodes"]["items"][0]["task_id"] == "failed-task"
    serialized = json.dumps(payload)
    assert "must-not-leak" not in serialized
    assert "api_key" not in serialized
    assert "private" not in serialized


def test_dashboard_lists_are_strictly_bounded_and_queries_do_not_select_raw_json(app, client):
    now = datetime.now(UTC).replace(tzinfo=None)
    with app.state.session_factory() as session:
        _add_task(session, "large-task", status="completed", created_at=now, unique_count=40)
        for index in range(1, 41):
            _add_result(
                session,
                "large-task",
                index,
                country=f"Country-{index}",
                province=f"Region-{index}",
                severity=f"severity-{index}",
                labels=[f"label-{index}"],
            )
        session.commit()

    statements: list[str] = []

    def record_sql(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement.lower())

    event.listen(app.state.engine, "before_cursor_execute", record_sql)
    try:
        overview = client.get("/api/dashboard?mode=overview").json()
        landscape = client.get("/api/dashboard?mode=landscape").json()
    finally:
        event.remove(app.state.engine, "before_cursor_execute", record_sql)

    assert len(overview["sections"]["recent_risks"]["items"]) <= 8
    assert len(landscape["sections"]["countries"]["items"]) <= 10
    assert len(landscape["sections"]["regions"]["items"]) <= 10
    assert len(landscape["sections"]["labels"]["items"]) <= 10
    assert all("raw_json" not in statement for statement in statements)
