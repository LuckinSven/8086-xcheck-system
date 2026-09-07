import json
import struct
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_package_metadata_declares_apache_2_license():
    with (ROOT / "pyproject.toml").open("rb") as stream:
        backend = tomllib.load(stream)
    frontend = json.loads((ROOT / "frontend/package.json").read_text(encoding="utf-8"))

    assert backend["project"]["license"] == "Apache-2.0"
    assert frontend["license"] == "Apache-2.0"


def test_container_build_copies_license_files_before_installing_the_package():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    copy_position = dockerfile.index("COPY pyproject.toml LICENSE NOTICE ./")
    install_position = dockerfile.index("RUN pip install --no-cache-dir .")

    assert copy_position < install_position


def test_readmes_embed_the_versioned_homepage_screenshot():
    for filename in ("README.md", "README.zh-CN.md"):
        readme = (ROOT / filename).read_text(encoding="utf-8")
        assert "](docs/images/xcheck-homepage.png)" in readme
        assert "Apache-2.0" in readme


def test_homepage_screenshot_has_the_documented_dimensions():
    content = (ROOT / "docs/images/xcheck-homepage.png").read_bytes()
    assert content[:8] == b"\x89PNG\r\n\x1a\n"
    width, height = struct.unpack(">II", content[16:24])
    assert (width, height) == (1600, 1000)
