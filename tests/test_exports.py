import io
import json

from openpyxl import load_workbook
from xcheck.models import TaskIP, ThreatbookBatch, ThreatbookResult, WhitelistResult


def _wait_for_task(client, task_id):
    import time

    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        task = client.get(f"/api/tasks/{task_id}").json()
        if task["unique_count"]:
            return task
        time.sleep(0.02)
    return task


def test_deduplicated_stage_exports_txt_and_xlsx(client):
    task_id = client.post("/api/tasks/manual", json={"text": "8.8.8.8\n8.8.8.8\n1.1.1.1"}).json()["id"]
    _wait_for_task(client, task_id)

    text_response = client.get(f"/api/tasks/{task_id}/exports/deduplicated.txt")
    assert text_response.status_code == 200
    assert "8.8.8.8\t4\t2" in text_response.text

    excel_response = client.get(f"/api/tasks/{task_id}/exports/deduplicated.xlsx")
    assert excel_response.status_code == 200
    workbook = load_workbook(io.BytesIO(excel_response.content), read_only=True)
    rows = list(workbook.active.values)
    assert rows[0][:3] == ("IP", "IP版本", "出现次数")
    assert len(rows) == 3


def test_unknown_export_stage_is_rejected(client):
    task_id = client.post("/api/tasks/manual", json={"text": "8.8.8.8"}).json()["id"]
    response = client.get(f"/api/tasks/{task_id}/exports/unknown.txt")
    assert response.status_code == 404


def test_invalid_stage_export_contains_original_bad_value(client):
    task_id = client.post("/api/tasks/manual", json={"text": "8.8.8.8\n错误地址"}).json()["id"]
    _wait_for_task(client, task_id)
    response = client.get(f"/api/tasks/{task_id}/exports/invalid.txt")
    assert response.status_code == 200
    assert "错误地址" in response.text


def test_stage_exports_use_whitelist_and_threatbook_snapshots(client, app):
    task_id = client.post("/api/tasks/manual", json={"text": "8.8.8.8\n1.1.1.1"}).json()["id"]
    _wait_for_task(client, task_id)
    with app.state.session_factory() as session:
        ips = session.query(TaskIP).filter(TaskIP.task_id == task_id).order_by(TaskIP.id).all()
        session.add(
            WhitelistResult(
                task_ip_id=ips[0].id,
                result_code="active",
                verdict="命中",
                matches_json="[]",
                raw_json="{}",
            )
        )
        session.add(
            WhitelistResult(
                task_ip_id=ips[1].id,
                result_code="not_found",
                verdict="未命中",
                matches_json="[]",
                raw_json="{}",
            )
        )
        batch = ThreatbookBatch(
            task_id=task_id,
            batch_number=1,
            status="completed",
            addresses_json=json.dumps([ips[1].normalized_ip]),
        )
        session.add(batch)
        session.flush()
        session.add(
            ThreatbookResult(
                task_ip_id=ips[1].id,
                batch_id=batch.id,
                is_malicious=True,
                confidence_level="high",
                severity="high",
                judgments_json='["Scanner"]',
            )
        )
        session.commit()

    hits = client.get(f"/api/tasks/{task_id}/exports/whitelist_hits.txt").text
    malicious = client.get(f"/api/tasks/{task_id}/exports/malicious.txt").text
    high = client.get(f"/api/tasks/{task_id}/exports/high_confidence_malicious.txt").text
    assert "8.8.8.8" in hits and "1.1.1.1" not in hits
    assert "1.1.1.1" in malicious and "8.8.8.8" not in malicious
    assert "1.1.1.1" in high
