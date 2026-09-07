from xcheck.models import StepAttempt, Task, TaskStatus
from xcheck.services.pipeline import create_manual_task


def test_failed_task_exposes_attempt_evidence_and_can_retry(client, app):
    task_id = create_manual_task(app.state.session_factory, "8.8.8.8", app.state.settings)
    with app.state.session_factory() as session:
        task = session.get(Task, task_id)
        task.status = TaskStatus.FAILED.value
        task.current_step = "parse_input"
        task.error_summary = "模拟解析失败"
        session.add(
            StepAttempt(
                task_id=task_id,
                step_name="parse_input",
                attempt_number=1,
                status="failed",
                error_type="ParseError",
                error_message="模拟解析失败",
                safe_request_json='{"source":"upload"}',
            )
        )
        session.commit()

    response = client.get(f"/api/tasks/{task_id}/diagnostics")
    assert response.status_code == 200
    assert response.json()["attempts"][0]["error_type"] == "ParseError"
    assert response.json()["last_successful_checkpoint"] is None

    retry = client.post(f"/api/tasks/{task_id}/steps/parse_input/retry")
    assert retry.status_code == 202
