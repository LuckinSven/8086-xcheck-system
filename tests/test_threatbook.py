from threading import Event, Thread
from urllib.parse import quote

import httpx
from sqlalchemy import select
from xcheck.models import (
    DailyUsage,
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
from xcheck.services.threatbook import GlobalRateLimiter, ThreatBookClient, run_threatbook


def test_threatbook_persists_batches_and_results(app):
    factory = app.state.session_factory
    task_id = create_manual_task(factory, "8.8.8.8\n1.1.1.1", app.state.settings)
    ingest_task(factory, task_id, app.state.settings)
    with factory() as session:
        task = session.get(Task, task_id)
        task.status = TaskStatus.WAITING_THREATBOOK.value
        for item in session.scalars(select(TaskIP).where(TaskIP.task_id == task_id)):
            item.stage = "threatbook_ready"
        session.commit()

    def handler(request: httpx.Request):
        addresses = request.url.params["resource"].split(",")
        return httpx.Response(
            200,
            json={
                "response_code": 0,
                "verbose_msg": "Ok",
                "data": {
                    ip: {
                        "is_malicious": ip == "8.8.8.8",
                        "confidence_level": "high" if ip == "8.8.8.8" else "low",
                        "severity": "high" if ip == "8.8.8.8" else "info",
                        "judgments": ["Scanner"] if ip == "8.8.8.8" else [],
                    }
                    for ip in addresses
                },
            },
        )

    client = ThreatBookClient("https://example.test/ip", "secret", transport=httpx.MockTransport(handler))
    limiter = GlobalRateLimiter(100_000, sleeper=lambda _seconds: None)
    run_threatbook(factory, task_id, client, limiter, app.state.settings)

    with factory() as session:
        task = session.get(Task, task_id)
        results = session.scalars(select(ThreatbookResult)).all()
        assert task.status == TaskStatus.COMPLETED.value
        assert task.malicious_count == 1
        assert task.high_confidence_count == 1
        assert len(results) == 2
        assert "secret" not in "".join(result.raw_json for result in results)


def test_rate_limiter_calculates_wait_without_parallel_burst():
    sleeps = []
    times = iter([0.0, 0.0, 0.0])
    limiter = GlobalRateLimiter(600, clock=lambda: next(times), sleeper=sleeps.append)
    limiter.acquire(100)
    limiter.acquire(100)
    assert sleeps == [10.0]


def test_rate_limiter_reconfiguration_preserves_scheduling_debt():
    sleeps = []
    times = iter([0.0, 0.0, 0.0])
    limiter = GlobalRateLimiter(600, clock=lambda: next(times), sleeper=sleeps.append)
    limiter.acquire(100)
    limiter.reconfigure(1200)
    limiter.acquire(1)

    assert sleeps == [10.0]
    assert limiter.interval_per_ip == 0.05


def test_rate_reconfiguration_does_not_wait_for_an_active_throttle_sleep():
    sleeping = Event()
    release_sleep = Event()
    reconfigured = Event()

    def sleeper(_seconds):
        sleeping.set()
        release_sleep.wait(1)

    limiter = GlobalRateLimiter(600, clock=lambda: 0.0, sleeper=sleeper)
    limiter.acquire(100)
    acquire_thread = Thread(target=lambda: limiter.acquire(1))
    acquire_thread.start()
    assert sleeping.wait(0.2)

    reconfigure_thread = Thread(target=lambda: (limiter.reconfigure(1200), reconfigured.set()))
    reconfigure_thread.start()
    completed_without_waiting = reconfigured.wait(0.2)
    release_sleep.set()
    acquire_thread.join(1)
    reconfigure_thread.join(1)

    assert completed_without_waiting is True


def test_failed_threatbook_attempt_never_persists_encoded_api_key(app):
    factory = app.state.session_factory
    secret = "secret+/= value"
    app.state.settings.threatbook_max_retries = 0
    task_id = create_manual_task(factory, "8.8.8.8", app.state.settings)
    ingest_task(factory, task_id, app.state.settings)
    with factory() as session:
        task = session.get(Task, task_id)
        task.status = TaskStatus.WAITING_THREATBOOK.value
        session.scalar(select(TaskIP).where(TaskIP.task_id == task_id)).stage = "threatbook_ready"
        session.commit()

    encoded = quote(secret, safe="")

    class FailingClient:
        api_key = secret

        def query(self, _addresses):
            raise RuntimeError(f"request failed: https://example.test/ip?apikey={encoded}")

    run_threatbook(
        factory,
        task_id,
        FailingClient(),
        GlobalRateLimiter(100_000, sleeper=lambda _seconds: None),
        app.state.settings,
    )

    with factory() as session:
        attempt = session.scalar(select(StepAttempt).where(StepAttempt.task_id == task_id))
        task = session.get(Task, task_id)
        evidence = f"{attempt.error_message} {task.error_summary}"
        assert secret not in evidence
        assert quote(secret, safe="") not in evidence


def test_active_threatbook_run_snapshots_batch_size(app):
    factory = app.state.session_factory
    task_id = create_manual_task(
        factory,
        "8.8.8.8\n1.1.1.1\n9.9.9.9\n8.8.4.4",
        app.state.settings,
    )
    ingest_task(factory, task_id, app.state.settings)
    with factory() as session:
        task = session.get(Task, task_id)
        task.status = TaskStatus.WAITING_THREATBOOK.value
        for item in session.scalars(select(TaskIP).where(TaskIP.task_id == task_id)):
            item.stage = "threatbook_ready"
        session.commit()

    calls = 0

    def handler(request: httpx.Request):
        nonlocal calls
        calls += 1
        addresses = request.url.params["resource"].split(",")
        if calls == 1:
            app.state.settings.threatbook_batch_size = 1
        return httpx.Response(
            200,
            json={
                "response_code": 0,
                "verbose_msg": "Ok",
                "data": {ip: {"is_malicious": False} for ip in addresses},
            },
        )

    app.state.settings.threatbook_batch_size = 2
    app.state.settings.threatbook_max_retries = 0
    run_threatbook(
        factory,
        task_id,
        ThreatBookClient("https://example.test/ip", "secret", transport=httpx.MockTransport(handler)),
        GlobalRateLimiter(100_000, sleeper=lambda _seconds: None),
        app.state.settings,
    )

    with factory() as session:
        assert len(session.scalars(select(ThreatbookResult)).all()) == 4


def _ready_task(app, text: str) -> str:
    task_id = create_manual_task(app.state.session_factory, text, app.state.settings)
    ingest_task(app.state.session_factory, task_id, app.state.settings)
    with app.state.session_factory() as session:
        task = session.get(Task, task_id)
        task.status = TaskStatus.WAITING_THREATBOOK.value
        task.current_step = "threatbook_query"
        for item in session.scalars(select(TaskIP).where(TaskIP.task_id == task_id)):
            item.stage = "threatbook_ready"
        session.commit()
    return task_id


class _RecordingLimiter:
    def __init__(self):
        self.rates = []
        self.acquired = []

    def reconfigure(self, rate):
        self.rates.append(rate)

    def acquire(self, count):
        self.acquired.append(count)


def test_run_uses_persisted_task_config_for_batch_rate_budget_and_retries(app, monkeypatch):
    """Fails if runtime settings can diverge from the configuration shown for the task."""
    app.state.settings.threatbook_batch_size = 2
    app.state.settings.threatbook_safe_ips_per_minute = 321
    app.state.settings.threatbook_daily_budget = 10
    app.state.settings.threatbook_max_retries = 1
    task_id = _ready_task(app, "8.8.8.8\n1.1.1.1\n9.9.9.9")

    app.state.settings.threatbook_batch_size = 1
    app.state.settings.threatbook_safe_ips_per_minute = 999
    app.state.settings.threatbook_daily_budget = 1
    app.state.settings.threatbook_max_retries = 0
    monkeypatch.setattr("xcheck.services.threatbook.time.sleep", lambda _seconds: None)
    calls = []

    class RetryThenSucceed:
        api_key = "configured"

        def query(self, addresses):
            calls.append(list(addresses))
            if len(calls) == 1:
                raise RuntimeError("transient")
            return {
                "response_code": 0,
                "verbose_msg": "Ok",
                "data": {ip: {"is_malicious": False} for ip in addresses},
            }

    limiter = _RecordingLimiter()
    run_threatbook(app.state.session_factory, task_id, RetryThenSucceed(), limiter, app.state.settings)

    with app.state.session_factory() as session:
        task = session.get(Task, task_id)
        batches = session.scalars(
            select(ThreatbookBatch)
            .where(ThreatbookBatch.task_id == task_id)
            .order_by(ThreatbookBatch.batch_number)
        ).all()
        assert task.status == TaskStatus.COMPLETED.value
        assert [len(item) for item in calls] == [2, 2, 1]
        assert limiter.rates == [321]
        assert limiter.acquired == [2, 2, 1]
        assert [batch.attempt_count for batch in batches] == [2, 1]


def test_quota_resume_preserves_total_progress_and_continues_batch_numbers(app):
    """Fails if a quota resume replaces cumulative totals or restarts batch numbering."""
    app.state.settings.threatbook_batch_size = 2
    app.state.settings.threatbook_daily_budget = 2
    app.state.settings.threatbook_max_retries = 0
    task_id = _ready_task(app, "8.8.8.8\n1.1.1.1\n9.9.9.9")

    class Succeed:
        api_key = "configured"

        def query(self, addresses):
            return {
                "response_code": 0,
                "verbose_msg": "Ok",
                "data": {ip: {"is_malicious": False} for ip in addresses},
            }

    limiter = _RecordingLimiter()
    run_threatbook(app.state.session_factory, task_id, Succeed(), limiter, app.state.settings)
    with app.state.session_factory() as session:
        task = session.get(Task, task_id)
        step = session.scalar(
            select(TaskStep).where(TaskStep.task_id == task_id, TaskStep.name == "threatbook_query")
        )
        assert task.status == TaskStatus.PAUSED_QUOTA.value
        assert (step.progress_current, step.progress_total, step.current_batch, step.total_batches) == (
            2,
            3,
            1,
            2,
        )
        usage = session.scalar(select(DailyUsage))
        usage.successful_ips = 0
        task.status = TaskStatus.QUEUED.value
        session.commit()

    run_threatbook(app.state.session_factory, task_id, Succeed(), limiter, app.state.settings)

    with app.state.session_factory() as session:
        task = session.get(Task, task_id)
        step = session.scalar(
            select(TaskStep).where(TaskStep.task_id == task_id, TaskStep.name == "threatbook_query")
        )
        batches = session.scalars(
            select(ThreatbookBatch)
            .where(ThreatbookBatch.task_id == task_id)
            .order_by(ThreatbookBatch.batch_number)
        ).all()
        assert task.status == TaskStatus.COMPLETED.value
        assert task.failed_count == 0
        assert (step.progress_current, step.progress_total, step.current_batch, step.total_batches) == (
            3,
            3,
            2,
            2,
        )
        assert [batch.batch_number for batch in batches] == [1, 2]


def test_terminal_batch_failure_sets_counts_and_finish_timestamps(app):
    """Fails if failed execution leaves a running batch/step or unset failed counters."""
    app.state.settings.threatbook_batch_size = 1
    app.state.settings.threatbook_max_retries = 0
    task_id = _ready_task(app, "8.8.8.8\n1.1.1.1")
    calls = 0

    class SecondBatchFails:
        api_key = "configured"

        def query(self, addresses):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("upstream failure")
            return {
                "response_code": 0,
                "verbose_msg": "Ok",
                "data": {addresses[0]: {"is_malicious": False}},
            }

    run_threatbook(
        app.state.session_factory,
        task_id,
        SecondBatchFails(),
        GlobalRateLimiter(100_000, sleeper=lambda _seconds: None),
        app.state.settings,
    )

    with app.state.session_factory() as session:
        task = session.get(Task, task_id)
        step = session.scalar(
            select(TaskStep).where(TaskStep.task_id == task_id, TaskStep.name == "threatbook_query")
        )
        failed_batch = session.scalar(
            select(ThreatbookBatch).where(
                ThreatbookBatch.task_id == task_id, ThreatbookBatch.status == "failed"
            )
        )
        assert task.status == TaskStatus.PARTIAL_SUCCESS.value
        assert task.failed_count == 1
        assert step.status == StepStatus.FAILED.value
        assert step.finished_at is not None
        assert failed_batch.batch_number == 2
        assert failed_batch.finished_at is not None
        assert failed_batch.attempt_count == 1


def test_malformed_success_payload_terminalizes_failed_attempt_and_remains_retryable(
    app, client, monkeypatch
):
    """Fails if malformed successful upstream data leaves the task or batch running."""
    app.state.settings.threatbook_max_retries = 0
    app.state.settings.threatbook_api_key = "configured"
    task_id = _ready_task(app, "8.8.8.8")

    class MalformedSuccess:
        api_key = "configured"

        def query(self, _addresses):
            return {"response_code": 0, "verbose_msg": "contains upstream-secret", "data": []}

    run_threatbook(
        app.state.session_factory,
        task_id,
        MalformedSuccess(),
        GlobalRateLimiter(100_000, sleeper=lambda _seconds: None),
        app.state.settings,
    )

    submitted = []
    monkeypatch.setattr(app.state.worker, "submit_threatbook", submitted.append)
    with app.state.session_factory() as session:
        task = session.get(Task, task_id)
        step = session.scalar(
            select(TaskStep).where(TaskStep.task_id == task_id, TaskStep.name == "threatbook_query")
        )
        batch = session.scalar(select(ThreatbookBatch).where(ThreatbookBatch.task_id == task_id))
        attempt = session.scalar(select(StepAttempt).where(StepAttempt.task_id == task_id))
        assert task.status == TaskStatus.FAILED.value
        assert step.status == StepStatus.FAILED.value
        assert step.finished_at is not None
        assert batch.status == "failed"
        assert batch.finished_at is not None
        assert attempt.status == "failed"
        assert "upstream-secret" not in f"{task.error_summary} {attempt.error_message}"

    retry = client.post(f"/api/tasks/{task_id}/steps/threatbook_query/retry")
    assert retry.status_code == 202
    assert retry.json()["status"] == TaskStatus.QUEUED.value
    assert submitted == [task_id]


def test_result_persistence_failure_rolls_back_partial_batch_and_terminalizes(app):
    """Fails if a result persistence error escapes without a safe terminal transition."""
    app.state.settings.threatbook_max_retries = 0
    task_id = _ready_task(app, "8.8.8.8")
    with app.state.session_factory() as session:
        task_ip = session.scalar(select(TaskIP).where(TaskIP.task_id == task_id))
        prior_batch = ThreatbookBatch(
            id="prior-result-batch",
            task_id=task_id,
            batch_number=7,
            status="completed",
            addresses_json='["8.8.8.8"]',
            unresolved_json="[]",
        )
        session.add(prior_batch)
        session.add(
            ThreatbookResult(
                task_ip_id=task_ip.id,
                batch_id=prior_batch.id,
                is_malicious=False,
                judgments_json="[]",
                raw_json="{}",
            )
        )
        session.commit()

    class Succeed:
        api_key = "configured"

        def query(self, addresses):
            return {
                "response_code": 0,
                "verbose_msg": "Ok",
                "data": {addresses[0]: {"is_malicious": False}},
            }

    run_threatbook(
        app.state.session_factory,
        task_id,
        Succeed(),
        GlobalRateLimiter(100_000, sleeper=lambda _seconds: None),
        app.state.settings,
    )

    with app.state.session_factory() as session:
        task = session.get(Task, task_id)
        step = session.scalar(
            select(TaskStep).where(TaskStep.task_id == task_id, TaskStep.name == "threatbook_query")
        )
        failed_batch = session.scalar(
            select(ThreatbookBatch).where(
                ThreatbookBatch.task_id == task_id, ThreatbookBatch.status == "failed"
            )
        )
        assert task.status == TaskStatus.FAILED.value
        assert task.failed_count == 1
        assert step.finished_at is not None
        assert failed_batch.batch_number == 8
        assert failed_batch.finished_at is not None
