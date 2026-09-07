import json
from datetime import UTC, datetime

from sqlalchemy import text
from xcheck.models import Task, TaskIP, TaskStep, ThreatbookBatch, ThreatbookResult


def _add_task(session, task_id, *, status, created_at, filename=None, started=True):
    task = Task(
        id=task_id,
        status=status,
        input_type="csv" if filename else "manual",
        original_filename=filename,
        manual_text=None if filename else "8.8.8.8",
        current_step="threatbook_query",
        threatbook_ready_count=3,
        failed_count=1 if status == "partial_success" else 0,
        created_at=created_at,
        updated_at=created_at,
    )
    session.add(task)
    session.add(
        TaskStep(
            task_id=task_id,
            name="threatbook_query",
            status="completed" if status == "completed" else "failed",
            started_at=created_at if started else None,
            finished_at=created_at if status in {"completed", "partial_success"} else None,
        )
    )
    return task


def _add_batch(session, task_id, batch_id, batch_number, *, status="completed"):
    session.add(
        ThreatbookBatch(
            id=batch_id,
            task_id=task_id,
            batch_number=batch_number,
            status=status,
            addresses_json="[]",
            unresolved_json="[]",
        )
    )


def _add_result(
    session,
    task_id,
    batch_id,
    ip,
    *,
    malicious,
    judgments,
    country,
    province,
    city,
    severity,
    confidence,
):
    task_ip = TaskIP(
        task_id=task_id,
        raw_value=ip,
        normalized_ip=ip,
        ip_version=4,
        is_public=True,
        stage="threatbook_complete",
    )
    session.add(task_ip)
    session.flush()
    session.add(
        ThreatbookResult(
            task_ip_id=task_ip.id,
            batch_id=batch_id,
            is_malicious=malicious,
            confidence_level=confidence,
            severity=severity,
            judgments_json=json.dumps(judgments, ensure_ascii=False),
            country=country,
            province=province,
            city=city,
            raw_json="{}",
        )
    )


def _seed_history(factory):
    with factory() as session:
        _add_task(
            session,
            "task-old",
            status="completed",
            created_at=datetime(2026, 8, 10, 1, 0, tzinfo=UTC),
            filename="old.csv",
        )
        _add_batch(session, "task-old", "old-batch-1", 1)
        _add_batch(session, "task-old", "old-batch-2", 2)
        _add_result(
            session,
            "task-old",
            "old-batch-1",
            "8.8.8.8",
            malicious=True,
            judgments=["botnet", "100%_恶意"],
            country="中国",
            province="北京",
            city="北京市",
            severity="critical",
            confidence="high",
        )
        _add_result(
            session,
            "task-old",
            "old-batch-2",
            "8.8.4.4",
            malicious=False,
            judgments=["benign"],
            country="美国",
            province="加州",
            city="洛杉矶",
            severity="info",
            confidence="low",
        )

        _add_task(
            session,
            "task-new",
            status="partial_success",
            created_at=datetime(2026, 8, 12, 2, 0, tzinfo=UTC),
        )
        _add_batch(session, "task-new", "new-batch", 1)
        _add_result(
            session,
            "task-new",
            "new-batch",
            "1.1.1.1",
            malicious=True,
            judgments=["scanner"],
            country="澳大利亚",
            province="新南威尔士",
            city="悉尼",
            severity="high",
            confidence="medium",
        )

        _add_task(
            session,
            "task-failed",
            status="failed",
            created_at=datetime(2026, 8, 11, 1, 0, tzinfo=UTC),
        )
        _add_batch(session, "task-failed", "failed-batch", 1, status="failed")

        _add_task(
            session,
            "task-never-started",
            status="waiting_threatbook_confirmation",
            created_at=datetime(2026, 8, 13, 1, 0, tzinfo=UTC),
            started=False,
        )
        _add_task(
            session,
            "task-paused-before-batch",
            status="paused_quota",
            created_at=datetime(2026, 8, 9, 1, 0, tzinfo=UTC),
        )
        session.commit()


def test_history_has_one_record_per_started_task_and_page_scoped_aggregates(app, client):
    """Fails if batches duplicate history rows or tasks without ThreatBook work are included."""
    _seed_history(app.state.session_factory)

    response = client.get("/api/threatbook/history?page=1&page_size=2")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 4
    assert payload["page"] == 1
    assert payload["page_size"] == 2
    assert [item["task_id"] for item in payload["items"]] == ["task-new", "task-failed"]
    assert payload["items"][0] == {
        "task_id": "task-new",
        "source_name": "手动输入",
        "status": "partial_success",
        "ready_count": 3,
        "completed_count": 1,
        "failed_count": 1,
        "malicious_count": 1,
        "labels": ["scanner"],
        "label_remaining_count": 0,
        "regions": ["澳大利亚 / 新南威尔士 / 悉尼"],
        "region_remaining_count": 0,
        "created_at": "2026-08-12T02:00:00",
        "started_at": "2026-08-12T02:00:00",
        "finished_at": "2026-08-12T02:00:00",
    }
    assert payload["items"][1]["labels"] == []
    assert payload["items"][1]["regions"] == []
    assert "task-never-started" not in response.text

    second_page = client.get("/api/threatbook/history?page=2&page_size=2")
    assert [item["task_id"] for item in second_page.json()["items"]] == [
        "task-old",
        "task-paused-before-batch",
    ]
    assert second_page.json()["items"][0]["labels"] == ["100%_恶意", "benign", "botnet"]
    assert second_page.json()["items"][0]["regions"] == [
        "中国 / 北京 / 北京市",
        "美国 / 加州 / 洛杉矶",
    ]


def test_history_result_filters_use_one_correlated_exists_and_task_filters(app, client):
    """Fails if result criteria can be satisfied by different rows or task/date filters are ignored."""
    _seed_history(app.state.session_factory)

    exact = client.get(
        "/api/threatbook/history",
        params={
            "q": "8.8.8",
            "malicious": "true",
            "judgment": "100%_恶意",
            "country": "中国",
            "province": "北京",
            "city": "北京市",
            "severity": "critical",
            "confidence": "high",
            "status": "completed",
            "date_from": "2026-08-09",
            "date_to": "2026-08-10",
        },
    )
    assert exact.status_code == 200
    assert [item["task_id"] for item in exact.json()["items"]] == ["task-old"]

    split_across_rows = client.get(
        "/api/threatbook/history", params={"malicious": "true", "country": "美国"}
    )
    assert split_across_rows.status_code == 200
    assert split_across_rows.json()["total"] == 0

    exact_tag = client.get("/api/threatbook/history", params={"judgment": "botnet"})
    assert [item["task_id"] for item in exact_tag.json()["items"]] == ["task-old"]
    assert client.get("/api/threatbook/history?page_size=201").status_code == 422


def test_filter_options_are_distinct_sorted_persisted_values(app, client):
    """Fails if filter controls omit stored labels/regions or return duplicate/null options."""
    _seed_history(app.state.session_factory)

    response = client.get("/api/threatbook/filter-options")

    assert response.status_code == 200
    assert response.json() == {
        "labels": ["100%_恶意", "benign", "botnet", "scanner"],
        "countries": ["中国", "澳大利亚", "美国"],
        "provinces": ["加州", "北京", "新南威尔士"],
        "cities": ["北京市", "悉尼", "洛杉矶"],
        "severities": ["critical", "high", "info"],
        "confidence_levels": ["high", "low", "medium"],
    }


def test_history_summaries_are_frequency_ranked_bounded_and_report_remaining_counts(app, client):
    """Fails if a task summary returns every distinct label/region or sorts them alphabetically."""
    with app.state.session_factory() as session:
        _add_task(
            session,
            "task-ranked",
            status="completed",
            created_at=datetime(2026, 8, 14, 2, 0, tzinfo=UTC),
        )
        _add_batch(session, "task-ranked", "ranked-batch", 1)
        fixtures = [
            ("8.8.8.1", ["common", "second", "third", "fourth"], "A"),
            ("8.8.8.2", ["common", "second", "third"], "A"),
            ("8.8.8.3", ["common", "second"], "B"),
            ("8.8.8.4", ["common"], "C"),
        ]
        for ip, judgments, country in fixtures:
            _add_result(
                session,
                "task-ranked",
                "ranked-batch",
                ip,
                malicious=False,
                judgments=judgments,
                country=country,
                province="",
                city="",
                severity="info",
                confidence="low",
            )
        session.commit()

    item = client.get("/api/threatbook/history?page_size=1").json()["items"][0]

    assert item["labels"] == ["common", "second", "third"]
    assert item["label_remaining_count"] == 1
    assert item["regions"] == ["A", "B"]
    assert item["region_remaining_count"] == 1


def test_filter_options_are_capped_before_materializing_global_vocabularies(app, client):
    """Fails if global option responses can grow without a caller-controlled upper bound."""
    _seed_history(app.state.session_factory)

    response = client.get("/api/threatbook/filter-options?limit=2")

    assert response.status_code == 200
    assert all(len(values) <= 2 for values in response.json().values())
    assert client.get("/api/threatbook/filter-options?limit=201").status_code == 422


def test_sqlite_filter_indexes_exist_after_repeated_initialization(app):
    """Fails if persisted databases miss idempotent compound indexes used by read filters."""
    from xcheck.database import create_sqlite_indexes

    create_sqlite_indexes(app.state.engine)
    create_sqlite_indexes(app.state.engine)
    with app.state.engine.connect() as connection:
        index_names = {
            row[0]
            for row in connection.execute(
                text(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'index' AND name LIKE 'ix_xcheck_%'"
                )
            )
        }

    assert {
        "ix_xcheck_tasks_status_created",
        "ix_xcheck_threatbook_batches_task_status",
        "ix_xcheck_threatbook_results_confidence",
        "ix_xcheck_threatbook_results_location",
        "ix_xcheck_threatbook_results_malicious",
        "ix_xcheck_threatbook_results_province",
        "ix_xcheck_threatbook_results_city",
        "ix_xcheck_threatbook_results_severity",
    }.issubset(index_names)


def test_sqlite_province_and_city_filters_use_dedicated_indexes(app):
    """Fails if province-only or city-only result filters require a 200k-row table scan."""
    with app.state.engine.connect() as connection:
        province_plan = " ".join(
            row[3]
            for row in connection.exec_driver_sql(
                "EXPLAIN QUERY PLAN "
                "SELECT id FROM threatbook_results WHERE province = ?",
                ("北京",),
            )
        )
        city_plan = " ".join(
            row[3]
            for row in connection.exec_driver_sql(
                "EXPLAIN QUERY PLAN "
                "SELECT id FROM threatbook_results WHERE city = ?",
                ("北京市",),
            )
        )

    assert province_plan.startswith("SEARCH")
    assert "USING COVERING INDEX ix_xcheck_threatbook_results_province" in province_plan
    assert city_plan.startswith("SEARCH")
    assert "USING COVERING INDEX ix_xcheck_threatbook_results_city" in city_plan
