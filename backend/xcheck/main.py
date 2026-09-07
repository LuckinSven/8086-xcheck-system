from contextlib import asynccontextmanager
from pathlib import Path
from threading import RLock

from fastapi import FastAPI
from fastapi.responses import FileResponse
from sqlalchemy import select, text

from .config import get_settings
from .database import Base, create_database_engine, create_sqlite_indexes, make_session_factory
from .worker import TaskWorker


def create_app() -> FastAPI:
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    engine = create_database_engine(settings.database_url)
    session_factory = make_session_factory(engine)
    settings_lock = RLock()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        from . import models  # noqa: F401

        Base.metadata.create_all(engine)
        create_sqlite_indexes(engine)
        from .models import Setting

        with session_factory() as session:
            for saved in session.scalars(select(Setting)):
                if not hasattr(settings, saved.key):
                    continue
                current = getattr(settings, saved.key)
                value = saved.value
                if isinstance(current, bool):
                    value = value.lower() in {"1", "true", "yes", "on"}
                elif isinstance(current, int):
                    value = int(value)
                setattr(settings, saved.key, value)
        app.state.engine = engine
        app.state.session_factory = session_factory
        app.state.settings = settings
        app.state.settings_lock = settings_lock
        app.state.worker = TaskWorker(session_factory, settings, settings_lock)
        app.state.worker.recover()
        yield
        app.state.worker.shutdown()
        engine.dispose()

    app = FastAPI(title="XCheck IP 信誉查询系统", version="0.1.0", lifespan=lifespan)

    from .api.exports import router as exports_router
    from .api.result_views import router as result_views_router
    from .api.settings import router as settings_router
    from .api.tasks import router as tasks_router
    from .api.threatbook_history import router as threatbook_history_router

    app.include_router(tasks_router)
    app.include_router(result_views_router)
    app.include_router(threatbook_history_router)
    app.include_router(exports_router)
    app.include_router(settings_router)

    @app.get("/api/health")
    def health() -> dict[str, str]:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"status": "ok", "database": "ready"}

    if (settings.static_dir / "index.html").exists():

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa_fallback(full_path: str):
            if full_path.startswith("api/"):
                from fastapi import HTTPException

                raise HTTPException(404, "Not Found")
            requested = settings.static_dir / full_path
            try:
                is_safe = requested.resolve().is_relative_to(settings.static_dir.resolve())
            except (OSError, ValueError):
                is_safe = False
            if is_safe and requested.is_file():
                return FileResponse(requested)
            return FileResponse(Path(settings.static_dir) / "index.html")

    return app


app = create_app()
