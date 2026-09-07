from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


def create_database_engine(database_url: str) -> Engine:
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False} if database_url.startswith("sqlite") else {},
    )
    if database_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def configure_sqlite(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    return engine


def create_sqlite_indexes(engine: Engine) -> None:
    if engine.dialect.name != "sqlite":
        return
    statements = (
        "CREATE INDEX IF NOT EXISTS ix_xcheck_tasks_status_created ON tasks(status, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_xcheck_threatbook_results_malicious "
        "ON threatbook_results(is_malicious)",
        "CREATE INDEX IF NOT EXISTS ix_xcheck_threatbook_results_severity "
        "ON threatbook_results(severity)",
        "CREATE INDEX IF NOT EXISTS ix_xcheck_threatbook_results_confidence "
        "ON threatbook_results(confidence_level)",
        "CREATE INDEX IF NOT EXISTS ix_xcheck_threatbook_results_location "
        "ON threatbook_results(country, province, city)",
        "CREATE INDEX IF NOT EXISTS ix_xcheck_threatbook_results_province "
        "ON threatbook_results(province)",
        "CREATE INDEX IF NOT EXISTS ix_xcheck_threatbook_results_city "
        "ON threatbook_results(city)",
        "CREATE INDEX IF NOT EXISTS ix_xcheck_threatbook_batches_task_status "
        "ON threatbook_batches(task_id, status)",
        "CREATE INDEX IF NOT EXISTS ix_xcheck_task_steps_name_status_task "
        "ON task_steps(name, status, task_id)",
    )
    with engine.begin() as connection:
        for statement in statements:
            connection.exec_driver_sql(statement)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
