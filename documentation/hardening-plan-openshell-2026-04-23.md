# Plan: Harden Clawith with OpenShell (NemoClaw-equivalence) — v2, post-review

## Context
Clawith is a multi-tenant OpenClaw-for-teams platform with no runtime sandboxing today: the `SubprocessBackend` in [backend/app/services/sandbox/local/subprocess_backend.py](../Clawith/backend/app/services/sandbox/local/subprocess_backend.py) relies on a pattern blocklist, not OS isolation. Agents can reach arbitrary URLs via poll triggers ([trigger_daemon.py](../Clawith/backend/app/services/trigger_daemon.py)), register unapproved MCP servers ([mcp_client.py](../Clawith/backend/app/services/mcp_client.py)), and ingest unsanitized external content via IM webhooks ([feishu.py](../Clawith/backend/app/api/feishu.py) and siblings).

This plan implements the NemoClaw-equivalence proposal at [documentation/Proposal_Hardening_Clawith_with_OpenShell_to_NemoClaw_Equivalence/](../Clawith/documentation/Proposal_Hardening_Clawith_with_OpenShell_to_NemoClaw_Equivalence/Proposal_Hardening_Clawith_with_OpenShell_to_NemoClaw_Equivalence.md), updated against the actual NemoClaw reference at `/home/hafnium/NemoClaw/` (v0.1.0, OpenShell v0.0.32) and revised per reviews from Security Engineer, Backend Architect, and DevOps agents. Reviewer amendments are marked **[A*]** below.

## Top deviations from the original proposal

| Original proposal | Adjusted | Reason |
|---|---|---|
| OpenShell v0.0.25 | **v0.0.32** | Fixes Landlock drop_privileges bug (NemoClaw issue #810). |
| Flat policy schema | NemoClaw schema: `filesystem_policy` (with `include_workdir: false`), `landlock`, `process`, `network_policies: {<name>: {endpoints, binaries}}` | **[A-sec-3]** Proposal's schema is pseudocode; NemoClaw's is the actual OpenShell v0.0.32 contract. |
| `binaries:` only on inference | `binaries:` on **every** preset | **[A-sec-1]** Without per-endpoint binary restriction, any Python-runnable builtin tool inside the sandbox reaches every allowlisted host. Restrict channel egress to the Runner Shim's binary only. |
| DLP Gate: regex + SHA-256 fingerprint | DLP Gate + canonicalization + entropy + markdown-link SSRF + workspace-write scan | **[A-sec-2]** Regex alone fails polymorphic exfil (base64, ROT13, paraphrase); Feishu card markdown is unescaped; intra-app workspace writes are an exfil channel. |
| Shields optional | Shields + **MFA/dual-control** on `POST /shields/down` + cooldown after agent-originated ApprovalRequests | **[A-sec-6]** Defends against social-engineering-via-agent. |
| Trigger middleware on outbound URL only | + webhook-token approval + `.md` deferred-materialization rule + cross-agent `on_message` approval | **[A-sec-4]** Webhook triggers are inbound (network allowlist doesn't apply); agents can write trigger directives to workspace `.md` files; A→B on_message is an exfil vector. |
| `kind` column added to ApprovalRequest | **Reuse existing `action_type`** with documented enum values | **[A-be-7]** `action_type String(100)` already exists; adding `kind` duplicates the axis. |
| Global `SANDBOX_OPENSHELL_ENABLED` | **Three-tier**: global flag → per-tenant column → per-agent `agent_sandboxes.status` | **[A-be-10]** Global + registry status are in tension; staged rollout needs tenant granularity. |
| `ssrf.py`, `credential_filter.py`, `dlp_gate.py` under `sandbox/openshell/` | **Hoisted to `backend/app/services/security/`** | **[A-be-3]** Generic security primitives; `trigger_daemon.py` already has inline SSRF that should consolidate. |
| Trigger middleware via FastAPI dependency | **Service-layer helper** `create_trigger_with_approval()` routed through every creation site | **[A-be-4]** Triggers are created in ≥3 places: API, two sites in [agent_tools.py](../Clawith/backend/app/services/agent_tools.py) (4730, 5923), migration script. A dependency misses the agent-tool path — the prompt-injection vector. |
| CLI `asyncio.create_subprocess_exec` from backend pod | **HTTP API on the gateway** with ServiceAccount + bearer token | **[A-do-9]** Cross-pod CLI exec requires shared socket/FS; HTTP is cleaner and gives an audit surface. CLI remains the gateway-local install tool. |
| `OpenShellBackend(SandboxBackend)` | **Sibling `AgentSandboxBackend` protocol**; `OpenShellBackend` implements both | **[A-be-1]** Existing `SandboxBackend` at [base.py:32-79](../Clawith/backend/app/services/sandbox/base.py) is a code-execution surface (`execute()`); OpenShell's per-agent lifecycle + policy hot-reload + streaming events doesn't fit. Don't break the seven existing backends. |

## Architecture

- **Layer 0 — Clawith Control Plane** (Python, unchanged).
- **Layer 1 — Sandbox Orchestrator** (new): `AgentSandboxBackend` sibling protocol + `OpenShellBackend` implementation. Security primitives (SSRF, credential filter, DLP) live at `backend/app/services/security/` and are reusable from `trigger_daemon`, channels, and MCP — not coupled to OpenShell.
- **Layer 2 — OpenShell Gateway** (pinned external, one Deployment per deployment). Backend calls its **HTTP API** with a ServiceAccount-issued bearer token; gateway stores policy state on a dedicated PVC.
- **Layer 3 — Per-agent sandbox** (new StatefulSet co-located with gateway via `topologyKey: kubernetes.io/hostname`). Hardened image derived from `ghcr.io/nvidia/openshell-community/openclaw@sha256:<pinned-in-phase-0>`.

## Files to create / modify

### New — sibling protocol + orchestrator
- `backend/app/services/sandbox/base.py` — add `AgentSandboxBackend` protocol (`ensure`, `apply_policy`, `sync_providers`, `dispatch_job -> AsyncIterator[AgentEvent]`, `teardown`, `get_status`). Existing `SandboxBackend` untouched. **[A-be-1]**
- `backend/app/services/sandbox/openshell/backend.py` — `OpenShellBackend(SandboxBackend, AgentSandboxBackend)`; `execute()` delegates to `dispatch_job()`.
- `backend/app/services/sandbox/openshell/orchestrator.py` — `SandboxOrchestrator` calling the **gateway's HTTP API** via `httpx.AsyncClient` with bearer auth. **[A-do-9]**
- `backend/app/services/sandbox/openshell/policy_compiler.py` — emits NemoClaw-schema YAML. Golden-file tests.
  - Applies the **multi-tenant-SaaS classification rule**: for any host flagged `multi_tenant_saas`, default `GET /**` allow + `POST` per-path enumerate-only (mirrors [openclaw-sandbox.yaml:90-110](/home/hafnium/NemoClaw/nemoclaw-blueprint/policies/openclaw-sandbox.yaml) Sentry pattern). **[A-sec-3]**
  - Resolves every host via `services/security/ssrf.py` **with DNS pinning**; stores pinned IPs in the policy and in `agent_sandboxes.pinned_ips` for trigger-poll re-check. **[A-sec-8]**
  - Emits `binaries:` restrictions on every preset, not just inference. **[A-sec-1]**
- `backend/app/services/sandbox/openshell/provider_sync.py` — reuses `get_model_api_key` from [llm/utils.py:49](../Clawith/backend/app/services/llm/utils.py#L49); adds sibling `get_provider_api_key(provider, org_id)` in the same module. **[A-be-9]**
- `backend/app/services/sandbox/openshell/shields.py` + DB-persisted state (see §Shields below). **[A-be-8]**
- `backend/app/services/sandbox/openshell/policies/` — base `openclaw-sandbox.yaml`, presets (slack/discord/feishu/wecom/dingtalk/telegram/npm/pypi/brave/jina/exa/anthropic/openai), `tiers.yaml` (restricted/balanced/open).

### New — security primitives (reusable, not OpenShell-specific) **[A-be-3]**
- `backend/app/services/security/ssrf.py` — Python port of [ssrf.ts](/home/hafnium/NemoClaw/nemoclaw/src/blueprint/ssrf.ts) **with DNS pinning**: `resolve_and_pin(host) -> (pinned_ip, ...)`. `trigger_daemon.py` replaces its inline `_is_private_url` ([lines 53-78](../Clawith/backend/app/services/trigger_daemon.py#L53-L78)) with this helper.
- `backend/app/services/security/credential_filter.py` — Python port of [credential-filter.ts](/home/hafnium/NemoClaw/src/lib/credential-filter.ts). Field-pattern scrubber.
- `backend/app/services/security/dlp_gate.py` — **runs without the sandbox**; works when `SANDBOX_OPENSHELL_ENABLED=False` for pre-sandbox defense-in-depth. **[A-sec-10]** Layers:
  1. Canonicalization: strip zero-width chars, NFKC Unicode, decode+rescan base64 blobs, normalize whitespace.
  2. Pattern match: regex for secret formats (API keys, JWTs, private keys).
  3. Entropy: Shannon entropy on 128-char windows > 4.5 bits/char → flag.
  4. Identity fingerprint: chunked SHA-256 overlap against `soul.md` / `memory.md`.
  5. **Markdown link-host allowlist**: every `[text](url)` and `![alt](url)` in agent output must resolve (via ssrf.resolve_and_pin) to a host already in the agent's `network_policies` allowlist.
  6. **Workspace-write hook**: when sandbox writes under `workspace/<task-id>/`, scan for identity-file content; hold if matched.

### New — trigger/MCP service-layer gates **[A-be-4, A-be-5]**
- `backend/app/services/triggers_service.py` — `create_trigger_with_approval(...)`. All creation sites (API, [agent_tools.py:4730](../Clawith/backend/app/services/agent_tools.py#L4730), [agent_tools.py:5923](../Clawith/backend/app/services/agent_tools.py#L5923)) route through this.
  - External-URL `poll`/`interval`: pending. **[A-sec-4]**
  - `webhook`: **pending even though inbound** (approval gates *token generation*, not URL). DLP applies to `_webhook_payload` before agent context injection.
  - Cross-agent `on_message` where source/target owners differ: pending unless explicit RBAC grant.
  - Periodic scanner for trigger-directive YAML front-matter in agent `.md` files; any such block blocks activation pending review.
- `backend/app/services/mcp_registry_service.py` — `register_mcp_tool(org_id, url, ...)`. Routes the six existing insertion sites through it ([resource_discovery.py:485, 520, 623, 651, 740](../Clawith/backend/app/services/resource_discovery.py), [atlassian.py:231](../Clawith/backend/app/api/atlassian.py#L231)). Migration backfills `mcp_registry` with `status='approved'` for all existing unique `(org_id, url)` to prevent live-integration breakage. **[A-be-5]**

### New — Runner Shim (sandbox image) **[A-sec-5, A-do-4]**
- `sandbox_runtime/runner_shim/` — new top-level directory:
  - `entrypoint.sh`, `runner/__main__.py`, `runner/protocol.py`, `runner/auth.py`.
  - **Strict Pydantic schema** with `extra="forbid"` on all inbound fields (`agent_id: UUID`, `task_id: UUID`, `workspace_path: Path`, `tool_name: str`, `args: dict`).
  - **Per-job short-lived JWT** (<5 min) scoped to one `agent_id`, signed by control plane; shim holds no long-lived Clawith credentials.
  - **Unique Unix socket per sandbox** with `SO_PEERCRED` check that the caller is the OpenShell gateway UID.
  - **Protocol versioned**: `shim_protocol_version: int` in every payload; control plane sends `min_supported`; mismatch → refuse + log. `shim_ver` column added to `agent_sandboxes`.

### New — sandbox image **[A-sec-7, A-do-2]**
- `sandbox_runtime/Dockerfile` — derived from `ghcr.io/nvidia/openshell-community/openclaw@sha256:<resolved-in-phase-0>`. Removes Smithery/ModelScope; installs Runner Shim; `USER sandbox` (no root); entrypoint includes `ulimit -c 0` to disable core dumps; `/tmp` remapped out of sandbox-writable (writes go to `/var/lib/clawith-agent/tmp`); Landlock rules exclude `/proc/*/mem`, `/proc/*/environ`; seccomp filter denies `ptrace` if OpenShell supports seccomp composition. CI fails if the digest is still `<TBD>`.
- `sandbox_runtime/.dockerignore`, `sandbox_runtime/README.md`.

### New — migrations (land all in Phase 1) **[A-be-6]**
- `<rev>_openshell_schema.py` — single migration, three tables/changes:
  - `agent_sandboxes(id, agent_id UNIQUE FK, sandbox_name, gateway_host, status, policy_hash, provider_hash, pinned_ips JSONB, image_tag, openshell_ver, shim_ver, tier, created_at, updated_at)`.
  - `mcp_registry(id, org_id FK, name, url, allowed_tools JSONB, approved_by, approved_at, status, UNIQUE(org_id, url))` + **data backfill** for existing approved servers.
  - `shields_state(id, org_id FK UNIQUE, is_down bool, down_until timestamptz nullable, reason text, dropped_by UUID FK, dropped_at timestamptz)` — DB-persisted auto-restore (reviewed in daemon). **[A-be-8]**
  - Documented `action_type` enum constants (no column change). **[A-be-7]**
  - `tenants` column: `openshell_enabled BOOLEAN DEFAULT FALSE` for per-tenant rollout. **[A-be-10]**

### New — API
- `backend/app/api/approvals.py` — CRUD on `ApprovalRequest`. Gated by `check_agent_access` + the role-hierarchy check already in `admin_update_user`.
- `backend/app/api/shields.py` — `GET /shields`, `POST /shields/down`, `POST /shields/up`. **MFA step** reusing existing auth. **Dual-control** (two distinct org-admins) when `duration > 5 min` or shield-drop requests reference agent-generated ApprovalRequests within 60 min. Appends `AuditLog` row + JSONL line. **[A-sec-6]**
- `backend/app/api/sandboxes.py` — list, rebuild, logs.

### New — frontend
- `frontend/src/pages/ApprovalQueue.tsx`, `Shields.tsx`, `SandboxRegistry.tsx`.

### New — ops / infra
- `helm/clawith/templates/openshell-gateway.yaml` — **single Deployment, replicas=1**, with `podAntiAffinity` + dedicated PVC at `/var/lib/openshell`. **[A-do-1]**
- `helm/clawith/templates/sandbox-statefulset.yaml` — sandbox `StatefulSet` pinned to gateway's node via `topologyKey`. **[A-do-1]**
- `helm/clawith/templates/networkpolicy-sandbox.yaml` — default-deny egress on sandbox pods; allow only `to: gateway-pod` on port 3128. **[A-do-6]**
- `helm/clawith/values.yaml` — nested `sandbox.openshell.{enabled, gatewayHost, gatewayPort, version, baseImage.registry, baseImage.digest, shimProtocolVersion}`. **[A-do-9]**
- `helm/clawith/templates/servicemonitor.yaml` + metrics listed below. **[A-do-12]**
- Mount PVC at **`/data`** (not `/data/agents`); put shields JSONL at `/data/shields-audit.{YYYYMM}.jsonl` with rotation + dual-write to `AuditLog`. **[A-do-11]**
- `docker-compose.openshell.yml` overlay for opt-in local dev; default compose stays `SUBPROCESS`. **[A-do-7]**
- `.github/workflows/pr.yaml` (Phase 1 — lint + `pytest` with `STUB=1`), `sandbox-image.yaml` (Phase 2 — build + push digest), `docker-pin-check.yaml` (weekly base-image update check, adapted from NemoClaw). **[A-do-8]**
- `scripts/install-openshell.sh` — mirrors NemoClaw's, but pulls OpenShell tarball from the **private registry** with a SHA-256 hash stored in Clawith's git (not downloaded). **[A-do-5]**

### Modified — backend
- `backend/app/services/sandbox/registry.py` — dispatch `SandboxType.OPENSHELL` → `OpenShellBackend`.
- `backend/app/services/trigger_daemon.py` — (1) replace `_is_private_url` with `services.security.ssrf.is_private_url`; (2) compare `agent_sandboxes.pinned_ips` at each poll to prevent DNS rebinding; (3) fold shields auto-restore into the existing tick loop (no new queue). **[A-be-8]**
- `backend/app/config.py` — add nested OpenShell config group.

## Reused existing utilities / schemas (all confirmed)
- `SandboxBackend` protocol and `SandboxType` registry — [backend/app/services/sandbox/base.py](../Clawith/backend/app/services/sandbox/base.py), [registry.py](../Clawith/backend/app/services/sandbox/registry.py).
- `ApprovalRequest` + `AuditLog` — [backend/app/models/audit.py:27](../Clawith/backend/app/models/audit.py#L27).
- `check_agent_access`, role-hierarchy check — [backend/app/core/permissions.py](../Clawith/backend/app/core/permissions.py), `admin_update_user` pattern.
- `get_model_api_key` — [backend/app/services/llm/utils.py:49](../Clawith/backend/app/services/llm/utils.py#L49).
- `encrypt_data`/`decrypt_data` — [backend/app/core/security.py](../Clawith/backend/app/core/security.py).
- Agent data layout confirmed in [agent_context.py:14-19](../Clawith/backend/app/services/agent_context.py#L14-L19).

## Audit event kinds (added to `AuditLog` via Phase 3) **[A-sec-9]**

Nine Clawith-side mutations not covered by OpenShell's OCSF feed:
`approval.approve`, `approval.reject`, `shields.down`, `shields.up`, `policy.recompile`, `sandbox.create|rebuild|delete`, `provider.sync`, `mcp_registry.approve|reject`, `trigger.create_pending|activate_on_approval`, `dlp.hold|release|discard`.

## Observability **[A-do-12]**

Prometheus metrics emitted by the backend:
- `clawith_sandbox_active{tier}` gauge
- `clawith_sandbox_lifecycle_total{event=create|rebuild|policy_reload|drain|destroy}` counter
- `clawith_shields_down{org_id}` gauge, `clawith_shields_drop_total{reason}` counter
- `clawith_approval_pending{action_type}` gauge
- `clawith_policy_compile_duration_seconds` histogram
- `clawith_dlp_blocks_total{detector=regex|entropy|fingerprint|markdown_link|workspace_write}` counter
- `clawith_openshell_gateway_up` gauge

Alerts: shields down > 30 min (timer failed), policy-compile errors, sandbox lifecycle failure rate > 1%, approval backlog > 20.

## Execution phases

**Phase 0 — Prerequisites (must land before Phase 1 PRs)**
- Resolve and pin the OpenShell base image SHA-256 digest. CI rejects `<TBD>`. **[A-do-2]**
- Add `.github/workflows/pr.yaml` (lint + pytest with `STUB=1`). **[A-do-8]**
- Add `backend/tests/conftest.py` with shared tenant/agent/user fixtures. **[A-be-11]**

**Phase 1 — Foundation (backend-only, fully gated)**
1. Single Alembic migration landing all schema (agent_sandboxes, mcp_registry, shields_state, tenants.openshell_enabled). Includes MCP backfill. **[A-be-6, A-be-5]**
2. `AgentSandboxBackend` protocol + `OpenShellBackend` skeleton with `STUB=1` mode.
3. `PolicyCompiler` emitting NemoClaw YAML with the multi-tenant-SaaS classifier + per-endpoint `binaries`; golden-file tests with byte-equality. **[A-sec-1, A-sec-3]**
4. `ProviderSyncService` reusing `get_model_api_key`.
5. `services/security/{ssrf,credential_filter,dlp_gate}.py` with unit tests including entropy, canonicalization, workspace-write hook.
6. Trigger daemon wired to the new SSRF helper + pinned-IP enforcement at each poll.

**Phase 2 — Sandbox image + Runner Shim**
7. `sandbox_runtime/Dockerfile`; CI builds + pushes; digest recorded in `values.yaml`.
8. Runner Shim with versioned protocol, SO_PEERCRED socket, Pydantic `extra="forbid"`, per-job JWT.
9. Gateway HTTP API client; end-to-end stub test with `STUB=1`.
10. Sandbox StatefulSet + gateway Deployment + NetworkPolicy Helm templates.
11. `sandboxes` API + registry UI.

**Phase 3 — Approvals, shields, DLP, audit** **[A-sec-10, A-sec-4, A-sec-6, A-sec-9]**
12. `triggers_service.create_trigger_with_approval` routed through all creation sites; webhook-token approval; `.md` trigger-directive scanner.
13. `mcp_registry_service` routed through six insertion sites.
14. On approval → policy recompile + push via gateway HTTP API. Call **gated on `agent_sandboxes.status='running'`** so it no-ops cleanly when OpenShell is off. **[A-sec-10]**
15. DLP gate wired into agent-output path and workspace-write hook. Works without the sandbox.
16. `shields` API + MFA + dual-control + 60-min cooldown after agent-originated approvals; auto-restore via trigger-daemon tick reading `shields_state.down_until`.
17. All nine `AuditLog` event kinds emitted.

**Phase 4 — Integration + gradual flip** **[A-be-10]**
18. End-to-end tests exercise every threat from proposal §2 against a live sandbox, plus DLP-holds-when-sandbox-off regression.
19. Benchmark gateway with N ∈ {10, 50, 100, 500} sandboxes; confirm agent-hibernation state-machine (`agent_sandboxes.status='frozen'`) holds under load. **[A-do-3]**
20. Per-tenant opt-in: flip `tenants.openshell_enabled=true` on one staging tenant for 1-week burn-in.
21. Flip default for new agents in each tenant as operators approve.

**Phase 5 — deferred**
- Per-tenant gateways; GPU passthrough; production migration of existing agents via snapshot/restore ported from [snapshot.ts](/home/hafnium/NemoClaw/nemoclaw/src/blueprint/snapshot.ts).

## Verification

### Phase 0
- `git grep '<TBD>'` in `values.yaml` returns nothing.
- `.github/workflows/pr.yaml` runs pytest with `STUB=1` on every PR.

### Phase 1
- `pytest backend/tests/test_policy_compiler.py backend/tests/test_ssrf.py backend/tests/test_credential_filter.py backend/tests/test_dlp_gate.py backend/tests/test_provider_sync.py -v` → all pass.
- Golden-file test: compiled YAML byte-identical to fixture.
- `alembic upgrade head` + `alembic downgrade base` round-trip.
- Backfill test: seed 3 existing `Tool(type='mcp', ...)` rows; run migration; assert three `mcp_registry` rows with `status='approved'`.

### Phase 2
- `docker build sandbox_runtime/` succeeds; `docker run --rm <image> which smithery || echo REMOVED` outputs `REMOVED`.
- Shim protocol-mismatch test: shim with version=2, control plane sending `min_supported=3` → shim refuses and logs.
- `STUB=1` integration test dispatches a chat job and sees expected event stream.

### Phase 3
- Integration test: create `poll` trigger with `https://example.com/rss` → trigger row inactive, `ApprovalRequest(action_type='trigger_external_url')` pending. Approve → trigger activates, `openshell policy set` called, `example.com` in allowlist.
- Webhook test: create webhook trigger → token generation pending; approve → token issued.
- DLP regression with `SANDBOX_OPENSHELL_ENABLED=False`: agent output containing `soul.md` fingerprint → held; approval path works independent of sandbox.
- Canonicalization: agent posts base64-encoded secret via Slack tool → decoded, flagged, held.
- Shields: `POST /shields/down { duration_minutes: 10, reason: "debug" }` after MFA + dual-control → policy relaxed, JSONL + AuditLog written; at T+10 min auto-restore from daemon tick.
- Same-tenant role escalation attempt on `/shields/down` → 403 (role-hierarchy check wired).

### Phase 4
- Exercise every threat from proposal §2 against a live OpenShell-wrapped agent; all blocked.
- OCSF events from OpenShell land in `AuditLog` alongside the nine Clawith-side kinds.
- Load test: 500 active sandboxes with 10% hibernation; gateway memory < 80% of limit.
- Rollback drill: flip tenant off, assert agents execute via SubprocessBackend, pending approvals remain visible but inert.

## Pinned dependency versions

| Dependency | Pin | Source |
|---|---|---|
| OpenShell | `v0.0.32` | [install-openshell.sh](/home/hafnium/NemoClaw/scripts/install-openshell.sh) |
| OpenShell community base image | `ghcr.io/nvidia/openshell-community/openclaw@sha256:<resolved-in-Phase-0>` | Phase 0 output |
| NemoClaw reference (read-only) | HEAD @ d9aced49 | local clone |

Treat OpenShell upgrades as explicit migration events: bump pin, re-run Phase 1 golden tests, drain sandboxes, rebuild, rehydrate.

## Execution log — 2026-04-24

- ✅ Phase 0 item: added PR workflow at `.github/workflows/pr.yaml` to run `ruff` and `pytest` with `STUB=1` on pull requests.
- ✅ Phase 0 item: added shared test fixtures at `backend/tests/conftest.py` for tenant/identity/user/agent objects.
- ⚠️ Phase 0 item (base-image digest pin) remains blocked in this environment because the private OpenShell registry credentials are not available to resolve and verify the digest.

## Execution log — 2026-04-24 (follow-up review fixes)

- ✅ Updated `.github/workflows/pr.yaml` to remove ineffective `STUB=1`, add `permissions: contents: read`, add `concurrency` cancellation, and enable pip cache.
- ✅ Scoped initial `ruff` execution to `tests/conftest.py` and `tests/test_auth.py` to avoid unrelated baseline lint debt blocking Phase 0 bootstrap.
- ✅ Updated `backend/tests/conftest.py` to randomize `Identity.email`, use `hash_password("test-password")`, and document that fixtures return detached objects that must be explicitly persisted by tests.
