from concurrent.futures import ThreadPoolExecutor
from threading import RLock

from sqlalchemy import select

from .models import Task, TaskStatus
from .services.pipeline import ingest_task
from .services.threatbook import GlobalRateLimiter, ThreatBookClient, run_threatbook
from .services.whitelist import WhitelistClient, run_whitelist


class TaskWorker:
    def __init__(self, session_factory, settings, settings_lock=None):
        self.session_factory = session_factory
        self.settings = settings
        self.settings_lock = settings_lock or RLock()
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="xcheck-worker")
        self.limiter = GlobalRateLimiter(settings.threatbook_safe_ips_per_minute)

    def settings_snapshot(self):
        with self.settings_lock:
            return self.settings.model_copy(deep=True)

    def apply_runtime_settings(self, settings) -> None:
        with self.settings_lock:
            if settings.threatbook_safe_ips_per_minute != self.settings.threatbook_safe_ips_per_minute:
                self.limiter.reconfigure(settings.threatbook_safe_ips_per_minute)
            self.settings = settings

    def submit_ingest(self, task_id: str) -> None:
        self.executor.submit(self._ingest_and_whitelist, task_id)

    def _ingest_and_whitelist(self, task_id: str) -> None:
        settings = self.settings_snapshot()
        try:
            ingest_task(self.session_factory, task_id, settings)
            run_whitelist(
                self.session_factory,
                task_id,
                WhitelistClient(settings.whitelist_api_url),
            )
        except Exception:
            return

    def submit_threatbook(self, task_id: str) -> None:
        self.executor.submit(self._run_threatbook, task_id)

    def _run_threatbook(self, task_id: str) -> None:
        settings = self.settings_snapshot()
        try:
            run_threatbook(
                self.session_factory,
                task_id,
                ThreatBookClient(settings.threatbook_api_url, settings.threatbook_api_key),
                self.limiter,
                settings,
            )
        except Exception:
            return

    def recover(self) -> None:
        settings = self.settings_snapshot()
        with self.session_factory() as session:
            tasks = session.scalars(
                select(Task).where(
                    Task.status.in_(
                        [
                            TaskStatus.QUEUED.value,
                            TaskStatus.RUNNING.value,
                            TaskStatus.PAUSED_QUOTA.value,
                        ]
                    )
                )
            ).all()
            for task in tasks:
                if task.current_step in {"threatbook_query", "archive_results"}:
                    if settings.threatbook_api_key and task.status != TaskStatus.PAUSED_QUOTA.value:
                        task.status = TaskStatus.QUEUED.value
                        session.commit()
                        self.submit_threatbook(task.id)
                elif task.status != TaskStatus.PAUSED_QUOTA.value:
                    self.submit_ingest(task.id)

    def shutdown(self) -> None:
        self.executor.shutdown(wait=False, cancel_futures=False)
