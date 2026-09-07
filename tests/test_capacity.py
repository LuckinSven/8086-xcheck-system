import csv
import os

import psutil
from xcheck.services.pipeline import create_file_task, ingest_task


def test_streams_two_hundred_thousand_csv_rows_with_bounded_memory(app, tmp_path):
    path = tmp_path / "large.csv"
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(["访问源 IP", "时间"])
        for index in range(200_000):
            value = index % 50_000
            writer.writerow([f"11.{value // 65536}.{(value // 256) % 256}.{value % 256}", index])

    process = psutil.Process(os.getpid())
    before = process.memory_info().rss
    task_id = create_file_task(app.state.session_factory, "csv", path.name, path, app.state.settings)
    ingest_task(app.state.session_factory, task_id, app.state.settings)
    after = process.memory_info().rss

    task = client_task(app.state.session_factory, task_id)
    assert task.raw_count == 200_000
    assert task.unique_count == 50_000
    assert after - before < 150 * 1024 * 1024


def client_task(factory, task_id):
    from xcheck.models import Task

    with factory() as session:
        return session.get(Task, task_id)
