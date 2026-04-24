"""Shared pytest fixtures for tenant/user/agent test data."""

from __future__ import annotations

import uuid

import pytest

from app.core.security import hash_password
from app.models.agent import Agent
from app.models.tenant import Tenant
# NOTE: this Identity is the global auth identity model used by User.identity;
# app.models.identity defines SSO/provider management models with similar names.
from app.models.user import Identity, User


@pytest.fixture
def tenant_fixture() -> Tenant:
    """Build a default tenant object for tests.

    The returned model is intentionally detached from any SQLAlchemy session.
    Tests that need persistence must add/flush it explicitly.
    """
    return Tenant(
        id=uuid.uuid4(),
        name="Acme Inc",
        slug=f"acme-{uuid.uuid4().hex[:8]}",
        im_provider="web_only",
        timezone="UTC",
    )


@pytest.fixture
def identity_fixture() -> Identity:
    """Build a default identity object for tests.

    The returned model is intentionally detached from any SQLAlchemy session.
    Tests that need persistence must add/flush it explicitly.
    """
    return Identity(
        id=uuid.uuid4(),
        email=f"member-{uuid.uuid4().hex[:8]}@example.com",
        username=f"member-{uuid.uuid4().hex[:8]}",
        password_hash=hash_password("test-password"),
        is_active=True,
        email_verified=True,
    )


@pytest.fixture
def user_fixture(tenant_fixture: Tenant, identity_fixture: Identity) -> User:
    """Build a default tenant-scoped user object for tests.

    The returned model is intentionally detached from any SQLAlchemy session.
    Tests that need persistence must add/flush it explicitly.
    """
    return User(
        id=uuid.uuid4(),
        identity_id=identity_fixture.id,
        tenant_id=tenant_fixture.id,
        display_name="Test Member",
        role="member",
        identity=identity_fixture,
    )


@pytest.fixture
def agent_fixture(tenant_fixture: Tenant, user_fixture: User) -> Agent:
    """Build a default agent object for tests.

    The returned model is intentionally detached from any SQLAlchemy session.
    Tests that need persistence must add/flush it explicitly.
    """
    return Agent(
        id=uuid.uuid4(),
        name="Test Agent",
        creator_id=user_fixture.id,
        tenant_id=tenant_fixture.id,
        role_description="Fixture agent",
        agent_type="native",
        status="creating",
    )
