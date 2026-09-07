import time

from xcheck.models import Task
from xcheck.services.pipeline import create_manual_task
from xcheck.worker import TaskWorker


def test_worker_recovers_queued_ingest_task(app):
    task_id = create_manual_task(app.state.session_factory, "8.8.8.8", app.state.settings)
    worker = TaskWorker(app.state.session_factory, app.state.settings)
    try:
        worker.recover()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with app.state.session_factory() as session:
                task = session.get(Task, task_id)
                if task.unique_count == 1:
                    break
            time.sleep(0.02)
        assert task.unique_count == 1
    finally:
        worker.shutdown()
