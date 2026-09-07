from sqlalchemy import inspect


def test_schema_contains_durable_entities(app):
    names = set(inspect(app.state.engine).get_table_names())

    assert {
        "tasks",
        "task_steps",
        "task_ips",
        "whitelist_results",
        "threatbook_batches",
        "threatbook_results",
        "step_attempts",
        "daily_usage",
        "settings",
    } <= names


def test_sqlite_uses_wal_and_foreign_keys(app):
    with app.state.engine.connect() as connection:
        journal_mode = connection.exec_driver_sql("PRAGMA journal_mode").scalar_one()
        foreign_keys = connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one()

    assert journal_mode == "wal"
    assert foreign_keys == 1
