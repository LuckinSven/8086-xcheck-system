import json

from sqlalchemy import select
from xcheck.models import Task, TaskIP
from xcheck.services.pipeline import create_manual_task, ingest_task


def test_ingest_normalizes_deduplicates_and_counts(app):
    factory = app.state.session_factory
    task_id = create_manual_task(factory, "8.8.8.8\n8.8.8.8\n10.0.0.1\n错误地址")

    ingest_task(factory, task_id)

    with factory() as session:
        task = session.get(Task, task_id)
        ips = session.scalars(
            select(TaskIP).where(TaskIP.task_id == task_id).order_by(TaskIP.normalized_ip)
        ).all()
        assert task.raw_count == 4
        assert task.valid_count == 3
        assert task.invalid_count == 1
        assert task.unique_count == 2
        assert [(ip.normalized_ip, ip.occurrence_count, ip.is_public) for ip in ips] == [
            ("10.0.0.1", 1, False),
            ("8.8.8.8", 2, True),
        ]
        assert json.loads(ips[1].sample_positions) == ["item:1", "item:2"]
