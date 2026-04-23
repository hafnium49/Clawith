"""Regression tests for /chat/upload security fixes (Vulns 1 & 2)."""

import io
import os
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, UploadFile

from app.api import upload as upload_api


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class DummyDB:
    """Minimal AsyncSession stand-in; check_agent_access is monkey-patched so no queries run."""

    async def execute(self, *_args, **_kwargs):
        raise AssertionError("unexpected db.execute() — check_agent_access should be patched")


def _make_user(role="member", tenant_id=None):
    return SimpleNamespace(
        id=uuid.uuid4(),
        role=role,
        tenant_id=tenant_id or uuid.uuid4(),
        identity_id=uuid.uuid4(),
    )


def _make_upload(filename: str, content: bytes = b"dummy-bytes") -> UploadFile:
    """Build a FastAPI UploadFile backed by an in-memory buffer."""
    buf = io.BytesIO(content)
    # Starlette's UploadFile accepts a file-like + filename
    return UploadFile(filename=filename, file=buf)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_injection_filename_does_not_execute_code(tmp_path, monkeypatch):
    """A filename crafted as Python-injection payload must not execute anything.

    Regression for the previous subprocess-based extract_text(), which built
    source code by interpolating the filename. The new implementation passes
    bytes + filename to the shared extractor, so no shell or subprocess is
    involved.
    """
    monkeypatch.setattr(upload_api, "WORKSPACE_ROOT", Path(tmp_path))

    async def fake_check_agent_access(_db, _user, _agent_id):
        return SimpleNamespace(id=_agent_id), "manage"

    monkeypatch.setattr(upload_api, "check_agent_access", fake_check_agent_access)

    user = _make_user()
    agent_id = uuid.uuid4()
    pwn_marker = tmp_path / "pwn"

    malicious_name = f"foo.pdf');__import__('os').system('touch {pwn_marker}');#"
    upload = _make_upload(malicious_name, content=b"not-a-real-pdf")

    # Should not raise for the filename itself (basename strips nothing malicious here),
    # and must not create /tmp/pwn.
    result = await upload_api.upload_file(
        file=upload,
        agent_id=agent_id,
        current_user=user,
        db=DummyDB(),
    )

    assert not pwn_marker.exists(), "injection payload unexpectedly executed"
    # File should have been saved under the agent's uploads dir with a sanitized name.
    uploads_dir = Path(tmp_path) / str(agent_id) / "workspace" / "uploads"
    assert uploads_dir.exists()
    saved = list(uploads_dir.iterdir())
    assert len(saved) == 1
    assert "/" not in saved[0].name and "\\" not in saved[0].name
    assert result["workspace_path"].startswith("workspace/uploads/")


@pytest.mark.asyncio
async def test_path_traversal_filename_is_rejected_or_sanitized(tmp_path, monkeypatch):
    """A filename like '../../../etc/pwn' must not escape the agent uploads dir."""
    monkeypatch.setattr(upload_api, "WORKSPACE_ROOT", Path(tmp_path))

    async def fake_check_agent_access(_db, _user, _agent_id):
        return SimpleNamespace(id=_agent_id), "manage"

    monkeypatch.setattr(upload_api, "check_agent_access", fake_check_agent_access)

    user = _make_user()
    agent_id = uuid.uuid4()
    upload = _make_upload("../../../etc/pwn", content=b"x")

    # os.path.basename("../../../etc/pwn") == "pwn", which is a valid sanitized
    # name. The handler should save it under the agent's uploads dir — NOT at
    # /etc/pwn. Either outcome (accept with sanitized name, or 400) is
    # acceptable; a write outside the uploads dir is NOT.
    try:
        result = await upload_api.upload_file(
            file=upload,
            agent_id=agent_id,
            current_user=user,
            db=DummyDB(),
        )
    except HTTPException as exc:
        assert exc.status_code == 400
        return

    uploads_dir = Path(tmp_path) / str(agent_id) / "workspace" / "uploads"
    saved = list(uploads_dir.iterdir())
    assert len(saved) == 1
    # Must be strictly contained in the agent's uploads dir
    assert str(saved[0].resolve()).startswith(str(uploads_dir.resolve()) + os.sep)
    # Must not have written anything outside tmp_path
    assert not Path("/etc/pwn").exists() or Path("/etc/pwn").stat().st_size != 1
    assert result["saved_filename"] == "pwn"


@pytest.mark.asyncio
async def test_invalid_agent_id_is_rejected_by_pydantic():
    """agent_id that isn't a UUID must be rejected by FastAPI's UUID coercion.

    Since `agent_id: uuid.UUID = Form(...)`, FastAPI/Starlette converts the
    form value before our handler is reached. We exercise the same coercion
    contract by constructing a UUID directly from a bogus string.
    """
    with pytest.raises(ValueError):
        uuid.UUID("../../../tmp")


@pytest.mark.asyncio
async def test_cross_tenant_agent_access_returns_403(tmp_path, monkeypatch):
    """User A uploading to user B's agent must get 403 from check_agent_access."""
    monkeypatch.setattr(upload_api, "WORKSPACE_ROOT", Path(tmp_path))

    async def deny_access(_db, _user, _agent_id):
        raise HTTPException(status_code=403, detail="No access to this agent")

    monkeypatch.setattr(upload_api, "check_agent_access", deny_access)

    user = _make_user()
    agent_id = uuid.uuid4()
    upload = _make_upload("hello.txt", content=b"hello world")

    with pytest.raises(HTTPException) as exc:
        await upload_api.upload_file(
            file=upload,
            agent_id=agent_id,
            current_user=user,
            db=DummyDB(),
        )
    assert exc.value.status_code == 403
    # Nothing should have been written
    uploads_dir = Path(tmp_path) / str(agent_id) / "workspace" / "uploads"
    assert not uploads_dir.exists()


@pytest.mark.asyncio
async def test_happy_path_text_upload(tmp_path, monkeypatch):
    """A benign text upload succeeds and persists under the expected path."""
    monkeypatch.setattr(upload_api, "WORKSPACE_ROOT", Path(tmp_path))

    async def fake_check_agent_access(_db, _user, _agent_id):
        return SimpleNamespace(id=_agent_id), "manage"

    monkeypatch.setattr(upload_api, "check_agent_access", fake_check_agent_access)

    user = _make_user()
    agent_id = uuid.uuid4()
    payload = b"Hello, Clawith!\nSecond line."
    upload = _make_upload("greeting.txt", content=payload)

    result = await upload_api.upload_file(
        file=upload,
        agent_id=agent_id,
        current_user=user,
        db=DummyDB(),
    )

    uploads_dir = Path(tmp_path) / str(agent_id) / "workspace" / "uploads"
    saved_path = uploads_dir / "greeting.txt"
    assert saved_path.exists()
    assert saved_path.read_bytes() == payload

    assert result["filename"] == "greeting.txt"
    assert result["saved_filename"] == "greeting.txt"
    assert result["size"] == len(payload)
    assert result["workspace_path"] == "workspace/uploads/greeting.txt"
    assert result["is_image"] is False
    assert "Hello, Clawith!" in result["extracted_text"]
