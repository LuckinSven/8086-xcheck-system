from pathlib import Path

import yaml
from fastapi.testclient import TestClient


def test_spa_fallback_preserves_api_routes(tmp_path, monkeypatch):
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("<html>XCheck SPA</html>", encoding="utf-8")
    monkeypatch.setenv("STATIC_DIR", str(static))
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'spa.db'}")

    from xcheck.config import get_settings
    from xcheck.main import create_app

    get_settings.cache_clear()
    with TestClient(create_app()) as client:
        assert client.get("/tasks/example").text == "<html>XCheck SPA</html>"
        assert client.get("/api/does-not-exist").status_code == 404
    get_settings.cache_clear()


def test_compose_exposes_lan_port_and_persistent_data():
    compose_path = Path(__file__).parents[1] / "compose.yaml"
    payload = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    service = payload["services"]["xcheck"]

    assert "0.0.0.0:8086:8086" in service["ports"]
    assert "./data:/app/data" in service["volumes"]
    assert "host.docker.internal:host-gateway" in service["extra_hosts"]
    assert service["restart"] == "unless-stopped"
