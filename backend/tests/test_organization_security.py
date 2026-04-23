"""Regression tests for /org security fixes (Vuln 4 — IDOR / cross-tenant PATCH)."""

import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api import organization as org_api
from app.schemas.schemas import UserUpdate


# ---------------------------------------------------------------------------
# Fakes — reuse the DummyResult/RecordingDB shape from tests/test_auth.py and
# tests/test_chat_sessions_api.py so we stay consistent with project patterns.
# ---------------------------------------------------------------------------


class DummyResult:
    def __init__(self, values=None, scalar_value=None):
        self._values = list(values or [])
        self._scalar_value = scalar_value

    def scalar_one_or_none(self):
        if self._values:
            return self._values[0]
        return self._scalar_value

    def scalars(self):
        return self

    def all(self):
        return list(self._values)


class RecordingDB:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.added = []
        self.committed = False
        self.refreshed = []
        self.flushed = False

    async def execute(self, _statement, _params=None):
        if not self.responses:
            return DummyResult()
        return self.responses.pop(0)

    def add(self, value):
        self.added.append(value)

    async def commit(self):
        self.committed = True

    async def refresh(self, value):
        self.refreshed.append(value)

    async def flush(self):
        self.flushed = True


def _make_user(role="member", tenant_id=None, *, user_id=None):
    """Mirror the fake-user shape used in test_chat_sessions_api / test_auth."""
    return SimpleNamespace(
        id=user_id or uuid.uuid4(),
        identity_id=uuid.uuid4(),
        role=role,
        tenant_id=tenant_id or uuid.uuid4(),
        email="target@example.com",
        primary_mobile=None,
        display_name="Target User",
        username="target",
        is_active=True,
        identity=SimpleNamespace(
            id=uuid.uuid4(),
            email="target@example.com",
            username="target",
            phone=None,
        ),
    )


# ---------------------------------------------------------------------------
# admin_update_user — Fix 4 core assertions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_org_admin_cross_tenant_patch_is_forbidden(monkeypatch):
    """org_admin in tenant A PATCHing a user in tenant B → 403."""
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    current_user = _make_user(role="org_admin", tenant_id=tenant_a)
    target = _make_user(role="member", tenant_id=tenant_b)

    db = RecordingDB(responses=[DummyResult([target])])

    with pytest.raises(HTTPException) as exc:
        await org_api.admin_update_user(
            user_id=target.id,
            data=UserUpdate(display_name="Hacked"),
            current_user=current_user,
            db=db,
        )
    assert exc.value.status_code == 403
    assert db.committed is False


@pytest.mark.asyncio
async def test_org_admin_cannot_escalate_same_tenant_platform_admin(monkeypatch):
    """org_admin PATCHing a platform_admin in their own tenant → 403.

    This is the takeover chain the plan's role-hierarchy check closes: without
    it, an org_admin could change a platform_admin's email then trigger
    forgot-password to hijack the account.
    """
    tenant = uuid.uuid4()
    current_user = _make_user(role="org_admin", tenant_id=tenant)
    target = _make_user(role="platform_admin", tenant_id=tenant)

    db = RecordingDB(responses=[DummyResult([target])])

    with pytest.raises(HTTPException) as exc:
        await org_api.admin_update_user(
            user_id=target.id,
            data=UserUpdate(email="attacker@evil.example"),
            current_user=current_user,
            db=db,
        )
    assert exc.value.status_code == 403
    assert db.committed is False
    # Target's email must not have been mutated
    assert target.email == "target@example.com"


@pytest.mark.asyncio
async def test_org_admin_can_patch_regular_user_in_own_tenant(monkeypatch):
    """org_admin PATCHing a regular user in their own tenant → success."""
    tenant = uuid.uuid4()
    current_user = _make_user(role="org_admin", tenant_id=tenant)
    target = _make_user(role="member", tenant_id=tenant)

    # Two execute() calls: (1) load user, (2) no email/mobile change → none,
    # but we provide spare empty results in case the flow changes.
    db = RecordingDB(
        responses=[
            DummyResult([target]),
        ]
    )

    # Patch the response serializer so we don't need the full pydantic shape.
    class FakeUserOut:
        @staticmethod
        def model_validate(u):
            return SimpleNamespace(id=str(u.id), display_name=u.display_name)

    monkeypatch.setattr(org_api, "UserOut", FakeUserOut)

    result = await org_api.admin_update_user(
        user_id=target.id,
        data=UserUpdate(display_name="New Name"),
        current_user=current_user,
        db=db,
    )

    assert result.display_name == "New Name"
    assert target.display_name == "New Name"
    assert db.flushed is True


@pytest.mark.asyncio
async def test_platform_admin_can_patch_across_tenants(monkeypatch):
    """platform_admin PATCHing a user in any tenant → success."""
    current_user = _make_user(role="platform_admin", tenant_id=uuid.uuid4())
    target = _make_user(role="org_admin", tenant_id=uuid.uuid4())

    db = RecordingDB(responses=[DummyResult([target])])

    class FakeUserOut:
        @staticmethod
        def model_validate(u):
            return SimpleNamespace(id=str(u.id), display_name=u.display_name)

    monkeypatch.setattr(org_api, "UserOut", FakeUserOut)

    result = await org_api.admin_update_user(
        user_id=target.id,
        data=UserUpdate(display_name="By Platform Admin"),
        current_user=current_user,
        db=db,
    )
    assert result.display_name == "By Platform Admin"
    assert target.display_name == "By Platform Admin"


# ---------------------------------------------------------------------------
# list_users — cross-tenant filter restriction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_users_cross_tenant_filter_denied_for_org_admin(monkeypatch):
    """GET /org/users?tenant_id=<other> as org_admin must return ONLY own-tenant users.

    We capture the SQL Select that was executed and confirm the tenant filter
    was pinned to the caller's tenant_id, not the attacker-supplied one.
    """
    own_tenant = uuid.uuid4()
    other_tenant = uuid.uuid4()
    current_user = _make_user(role="org_admin", tenant_id=own_tenant)

    own_user = _make_user(role="member", tenant_id=own_tenant)

    # Capture the query that hits execute() so we can verify the effective filter.
    captured = {}

    class CapturingDB(RecordingDB):
        async def execute(self, statement, _params=None):
            captured["statement"] = statement
            return DummyResult([own_user])

    db = CapturingDB()

    class FakeUserOut:
        @staticmethod
        def model_validate(u):
            return SimpleNamespace(id=str(u.id), tenant_id=str(u.tenant_id))

    monkeypatch.setattr(org_api, "UserOut", FakeUserOut)

    result = await org_api.list_users(
        tenant_id=other_tenant,
        current_user=current_user,
        db=db,
    )

    # Must have returned only the own-tenant user.
    assert len(result) == 1
    assert result[0].tenant_id == str(own_tenant)
    # The rendered SQL should contain the caller's tenant_id, not the attacker's.
    # SQLAlchemy's literal_binds renders UUIDs as 32-char hex (no hyphens), so
    # compare on hex form.
    rendered = str(captured["statement"].compile(compile_kwargs={"literal_binds": True}))
    assert own_tenant.hex in rendered
    assert other_tenant.hex not in rendered
