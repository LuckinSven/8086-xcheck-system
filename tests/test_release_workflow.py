from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def load_workflow() -> dict:
    return yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_release_workflow_publishes_version_tags_with_minimal_permissions():
    workflow = load_workflow()

    assert workflow["on"]["push"]["tags"] == ["v*.*.*"]
    assert workflow["permissions"] == {"contents": "write", "packages": "write"}


def test_release_workflow_builds_multi_arch_image_and_creates_release():
    workflow = load_workflow()
    steps = workflow["jobs"]["publish"]["steps"]
    uses = [step.get("uses", "") for step in steps]
    metadata_step = next(step for step in steps if step.get("id") == "metadata")
    build_step = next(step for step in steps if step.get("id") == "build-and-push")
    release_step = next(step for step in steps if step.get("id") == "create-release")

    assert any(item.startswith("docker/login-action@") for item in uses)
    assert any(item.startswith("docker/metadata-action@") for item in uses)
    assert any(item.startswith("docker/build-push-action@") for item in uses)
    assert build_step["with"]["push"] == "true"
    assert build_step["with"]["platforms"] == "linux/amd64,linux/arm64"
    assert "type=semver,pattern={{version}}" in metadata_step["with"]["tags"]
    assert "type=semver,pattern={{raw}}" in metadata_step["with"]["tags"]
    assert "type=raw,value=latest" in metadata_step["with"]["tags"]
    assert build_step["with"]["tags"] == "${{ steps.metadata.outputs.tags }}"
    assert "gh release create" in release_step["run"]
    assert "--generate-notes" in release_step["run"]


def test_compose_defaults_to_the_published_container_image():
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    service = compose["services"]["xcheck"]

    assert service["image"] == "ghcr.io/luckinsven/8086-xcheck-system:${XCHECK_IMAGE_TAG:-latest}"


def test_readmes_document_the_release_image():
    for filename in ("README.md", "README.zh-CN.md"):
        readme = (ROOT / filename).read_text(encoding="utf-8")
        assert "ghcr.io/luckinsven/8086-xcheck-system:latest" in readme
        assert "docker compose pull" in readme
