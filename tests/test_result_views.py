import json
from datetime import UTC, datetime

from xcheck.models import TaskIP, ThreatbookBatch, ThreatbookResult, WhitelistResult
from xcheck.services.pipeline import create_manual_task


def test_whitelist_results_expose_categories_summary_pagination_and_filtering(app, client):
    """Fails if verdict rows are not joined, categorized, or filtered by their public conclusion."""
    factory = app.state.session_factory
    task_id = create_manual_task(factory, "8.8.8.8", app.state.settings)
    rows = [
        ("8.8.8.8", "active", "当前条目", [{"source": "current"}]),
        ("1.1.1.1", "reference", "历史条目", [{"source": "reference"}]),
        ("9.9.9.9", "inactive", "失效条目", [{"source": "inactive"}]),
        ("8.8.4.4", "not_found", "未命中条目", []),
        ("208.67.222.222", "invalid", "异常条目", [{"reason": "bad input"}]),
    ]
    with factory() as session:
        for index, (address, result_code, verdict, matches) in enumerate(rows, start=1):
            task_ip = TaskIP(
                task_id=task_id,
                raw_value=address,
                normalized_ip=address,
                ip_version=4,
                is_public=True,
                first_position=f"item:{index}",
                last_position=f"item:{index}",
            )
            session.add(task_ip)
            session.flush()
            session.add(
                WhitelistResult(
                    task_ip_id=task_ip.id,
                    request_id="req-whitelist",
                    result_code=result_code,
                    verdict=verdict,
                    matches_json=json.dumps(matches, ensure_ascii=False),
                    raw_json="{}",
                )
            )
        session.commit()

    response = client.get(f"/api/tasks/{task_id}/whitelist-results?page=1&page_size=2")

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"] == {"total": 5, "hit": 3, "clear": 1, "error": 1}
    assert payload["total"] == 5
    assert payload["page"] == 1
    assert payload["page_size"] == 2
    assert payload["items"] == [
        {
            "ip": "8.8.8.8",
            "category": "当前名单",
            "result_code": "active",
            "verdict": "当前条目",
            "matches": [{"source": "current"}],
            "request_id": "req-whitelist",
        },
        {
            "ip": "1.1.1.1",
            "category": "历史名单",
            "result_code": "reference",
            "verdict": "历史条目",
            "matches": [{"source": "reference"}],
            "request_id": "req-whitelist",
        },
    ]

    filtered = client.get(
        f"/api/tasks/{task_id}/whitelist-results?verdict=%E6%9C%AA%E5%91%BD%E4%B8%AD"
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1
    assert filtered.json()["items"] == [
        {
            "ip": "8.8.4.4",
            "category": "未命中",
            "result_code": "not_found",
            "verdict": "未命中条目",
            "matches": [],
            "request_id": "req-whitelist",
        }
    ]

    all_rows = client.get(f"/api/tasks/{task_id}/whitelist-results?page_size=200")
    assert [item["category"] for item in all_rows.json()["items"]] == [
        "当前名单",
        "历史名单",
        "失效名单",
        "未命中",
        "异常",
    ]


def test_threatbook_batches_are_paginated_summaries_without_sensitive_inputs(app, client):
    """Fails if batch reads leak input arrays/secrets or do not paginate execution records."""
    factory = app.state.session_factory
    app.state.settings.threatbook_api_key = "NEW-SECRET-KEY"
    task_id = create_manual_task(factory, "8.8.8.8", app.state.settings)
    with factory() as session:
        session.add_all(
            [
                ThreatbookBatch(
                    id="batch-1",
                    task_id=task_id,
                    batch_number=1,
                    status="completed",
                    addresses_json='["8.8.8.8", "1.1.1.1"]',
                    unresolved_json='["1.1.1.1"]',
                    attempt_count=2,
                    response_code=0,
                    response_message="accepted OLD-SECRET-KEY",
                    created_at=datetime(2026, 8, 14, 1, 0, tzinfo=UTC),
                    finished_at=datetime(2026, 8, 14, 1, 1, tzinfo=UTC),
                ),
                ThreatbookBatch(
                    id="batch-2",
                    task_id=task_id,
                    batch_number=2,
                    status="failed",
                    addresses_json='["9.9.9.9"]',
                    unresolved_json='["9.9.9.9"]',
                    attempt_count=4,
                    response_code=-1,
                    response_message="quota reached",
                ),
            ]
        )
        session.commit()

    response = client.get(f"/api/tasks/{task_id}/threatbook/batches?page=1&page_size=1")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    assert payload["page"] == 1
    assert payload["page_size"] == 1
    assert payload["items"] == [
        {
            "id": "batch-1",
            "batch_number": 1,
            "status": "completed",
            "address_count": 2,
            "resolved_count": 1,
            "unresolved_count": 1,
            "attempt_count": 2,
            "response_code": 0,
            "response_message": "微步接口请求完成",
            "created_at": "2026-08-14T01:00:00",
            "finished_at": "2026-08-14T01:01:00",
        }
    ]
    assert "8.8.8.8" not in response.text
    assert "OLD-SECRET-KEY" not in response.text
    assert "NEW-SECRET-KEY" not in response.text

    assert client.get("/api/tasks/missing/threatbook/batches").status_code == 404


def test_threatbook_results_paginate_and_intersect_exact_structured_filters(app, client):
    """Fails if result filters match different rows, partial JSON strings, or SQL wildcards."""
    factory = app.state.session_factory
    task_id = create_manual_task(factory, "8.8.8.8", app.state.settings)
    stored_ids = []
    with factory() as session:
        batch = ThreatbookBatch(
            id="result-batch",
            task_id=task_id,
            batch_number=1,
            status="completed",
            addresses_json="[]",
        )
        session.add(batch)
        fixtures = [
            (
                "8.8.8.8",
                True,
                "high",
                "critical",
                ["botnet", "100%_恶意"],
                "中国",
                "北京",
                "北京市",
                {"api_key": "must-not-leak", "basic": {"carrier": "测试运营商"}},
            ),
            (
                "1.1.1.1",
                False,
                "low",
                "info",
                ["benign"],
                "美国",
                "加州",
                "洛杉矶",
                {"token": "must-not-leak"},
            ),
            (
                "9.9.9.9",
                True,
                "high",
                "critical",
                ["botnet-extended"],
                "中国",
                "北京",
                "北京市",
                {},
            ),
            (
                "4.4.4.4",
                True,
                "high",
                "critical",
                ["100XX恶意"],
                "中国",
                "北京",
                "北京市",
                {},
            ),
        ]
        for index, fixture in enumerate(fixtures, start=1):
            ip, malicious, confidence, severity, judgments, country, province, city, raw = fixture
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
            result = ThreatbookResult(
                task_ip_id=task_ip.id,
                batch_id=batch.id,
                is_malicious=malicious,
                confidence_level=confidence,
                severity=severity,
                judgments_json=json.dumps(judgments, ensure_ascii=False),
                country=country,
                province=province,
                city=city,
                carrier="测试运营商" if index == 1 else None,
                asn_number=64500 if index == 1 else None,
                asn_name="测试 ASN" if index == 1 else None,
                scene="恶意软件" if index == 1 else None,
                update_time="2026-08-14 09:00:00" if index == 1 else None,
                permalink="https://example.test/ip/8.8.8.8" if index == 1 else None,
                raw_json=json.dumps(raw, ensure_ascii=False),
            )
            session.add(result)
            session.flush()
            stored_ids.append((result.id, task_ip.id))
        session.commit()

    first_page = client.get(f"/api/tasks/{task_id}/threatbook/results?page=1&page_size=2")

    assert first_page.status_code == 200
    assert first_page.json()["total"] == 4
    assert [item["ip"] for item in first_page.json()["items"]] == ["8.8.8.8", "1.1.1.1"]
    assert first_page.json()["items"][0] == {
        "id": stored_ids[0][0],
        "task_ip_id": stored_ids[0][1],
        "batch_id": "result-batch",
        "ip": "8.8.8.8",
        "is_malicious": True,
        "confidence_level": "high",
        "severity": "critical",
        "judgments": ["botnet", "100%_恶意"],
        "country": "中国",
        "province": "北京",
        "city": "北京市",
        "carrier": "测试运营商",
        "asn_number": 64500,
        "asn_name": "测试 ASN",
        "scene": "恶意软件",
        "update_time": "2026-08-14 09:00:00",
        "permalink": "https://example.test/ip/8.8.8.8",
    }
    assert "must-not-leak" not in first_page.text
    assert "raw" not in first_page.json()["items"][0]

    filtered = client.get(
        f"/api/tasks/{task_id}/threatbook/results",
        params={
            "q": "8.8.8",
            "malicious": "true",
            "judgment": "100%_恶意",
            "country": "中国",
            "province": "北京",
            "city": "北京市",
            "severity": "critical",
            "confidence": "high",
        },
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1
    assert [item["ip"] for item in filtered.json()["items"]] == ["8.8.8.8"]

    wildcard_tag = client.get(
        f"/api/tasks/{task_id}/threatbook/results", params={"judgment": "100%_恶意"}
    )
    assert [item["ip"] for item in wildcard_tag.json()["items"]] == ["8.8.8.8"]

    exact_tag = client.get(
        f"/api/tasks/{task_id}/threatbook/results", params={"judgment": "botnet"}
    )
    assert [item["ip"] for item in exact_tag.json()["items"]] == ["8.8.8.8"]
    assert client.get(f"/api/tasks/{task_id}/threatbook/results?page_size=201").status_code == 422
    assert client.get("/api/tasks/missing/threatbook/results").status_code == 404
