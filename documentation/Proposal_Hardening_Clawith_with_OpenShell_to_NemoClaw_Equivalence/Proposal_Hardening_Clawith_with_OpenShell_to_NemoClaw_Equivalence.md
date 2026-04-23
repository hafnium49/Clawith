The diagram rendering is noisy regardless of approach — I'll deliver the full written proposal instead which is more useful to a coding agent anyway.

***
# Proposal: Hardening Clawith with OpenShell to NemoClaw Equivalence
**Document status:** Ready to pass to a coding agent
**Prepared:** 2026-04-21
**Sources read:** [github.com/dataelement/Clawith](https://github.com/dataelement/Clawith) · [github.com/NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) · [github.com/NVIDIA/NemoClaw](https://github.com/NVIDIA/NemoClaw)

***
## 1. Executive summary
Clawith is a multi-tenant OpenClaw-for-teams platform (Python 3.12, FastAPI, PostgreSQL, Redis, React 19).  It has persistent per-agent workspaces, self-adaptive triggers, channel integrations, runtime tool installation, and MCP client support — none of which have security hardening today. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)

NemoClaw wraps a single OpenClaw instance in OpenShell (NVIDIA's declarative sandbox runtime written in Rust), achieving filesystem, process, network, and inference isolation enforced by policy YAML with zero modifications to OpenClaw's code. [github](https://github.com/NVIDIA/NemoClaw/blob/main/README.md)

This proposal implements equivalent protection for Clawith using an **inverted approach**: all security controls live in OpenShell policy YAML and a hardened sandbox image. **Clawith's Python source code is not patched.** Clawith upgrades are applied normally via `git pull && docker compose up -d --build`. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)

***
## 2. Threat model
The primary threat is **prompt-injection-driven data exfiltration**: malicious content enters through a document, MCP tool response, poll target, webhook, or channel message; the agent interprets it as instructions; it then attempts to leak data through model calls, HTTP requests, channel posts, self-created triggers, or newly installed tools. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)

Secondary threats: cross-agent data leakage (multi-tenancy), credential theft, persistent compromise via trigger installation, and MCP capability expansion. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)

***
## 3. Reference: what NemoClaw provides
From reading `github.com/NVIDIA/NemoClaw` and `github.com/NVIDIA/OpenShell`: [github](https://github.com/NVIDIA/NemoClaw/blob/main/README.md)

| OpenShell layer | What it enforces | When applied |
|---|---|---|
| Filesystem | Reads/writes outside `/sandbox` and `/tmp` blocked | Locked at sandbox creation |
| Process | Privilege escalation and dangerous syscalls blocked | Locked at sandbox creation |
| Network | Default-deny; only allowlisted hosts/methods/paths pass | Hot-reloadable |
| Inference | Model API calls intercepted, caller credentials stripped, backend credentials injected | Hot-reloadable |

Unlisted host requests are blocked and surfaced for operator approval in the OpenShell TUI (`openshell term`).  Credentials are injected as environment variables at runtime and **never written to the sandbox filesystem**. 

NemoClaw uses a versioned **blueprint** (a Python artifact) that orchestrates sandbox creation, policy application, and inference setup in a reproducible lifecycle: resolve → verify digest → plan → apply. [github](https://github.com/NVIDIA/NemoClaw/blob/main/README.md)

***
## 4. Architecture
The integration has four layers. Clawith is Layer 0 and is not modified.

```
┌─────────────────────────────────────────────────────────┐
│  Layer 0 · Clawith Control Plane  (no code changes)     │
│  FastAPI · PostgreSQL · Redis · Trigger Engine           │
│  JWT/RBAC · Approval Queue · OCSF Audit Store           │
└────────────────────┬────────────────────────────────────┘
                     │ job dispatch + trigger events
┌────────────────────▼────────────────────────────────────┐
│  Layer 1 · Sandbox Orchestrator  (new — ~5 components)  │
│  SandboxOrchestrator · Agent Sandbox Registry            │
│  Policy Compiler · Provider Sync · DLP Gate             │
└────────────────────┬────────────────────────────────────┘
         policy.yaml │ provider bundle
┌────────────────────▼────────────────────────────────────┐
│  Layer 2 · OpenShell Gateway  (pinned external)          │
│  Policy Engine · Inference Router · OCSF Log             │
└────────────────────┬────────────────────────────────────┘
        sandbox create│manage
┌────────────────────▼────────────────────────────────────┐
│  Layer 3 · Per-Agent Sandbox  (one per active agent)     │
│  Hardened Image · Scoped Mounts · Net Policy             │
│  Runner Shim · MCP Allowlist Client                      │
└─────────────────────────────────────────────────────────┘
```

Results flow upward through the DLP Gate before reaching Clawith's API or any channel integration. OCSF audit events flow from OpenShell Gateway into Clawith's audit log store.

***
## 5. New components to build
### 5.1 Hardened Sandbox Image
**What:** A custom Docker image derived from OpenShell's community base image, with Smithery and ModelScope binaries removed and a Runner Shim installed.

**Why:** OpenShell's filesystem and process policies are locked at sandbox creation.  Removing Smithery and ModelScope from the image means the agent physically cannot install new tools at runtime regardless of what Clawith's tools endpoint says. This directly prevents prompt-injection-induced tool installation from bypassing the locked process policy. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)

**How to build:**

```dockerfile
FROM ghcr.io/nvidia/openshell-community/openclaw:latest
# Remove runtime tool installers
RUN rm -rf /usr/local/bin/smithery \
           /usr/local/lib/node_modules/@smithery \
           /usr/local/bin/modelscope \
           /usr/local/lib/python*/site-packages/modelscope
# Install Runner Shim
COPY runner_shim/ /opt/clawith-shim/
RUN pip install -e /opt/clawith-shim
ENTRYPOINT ["/opt/clawith-shim/entrypoint.sh"]
```

**Maintenance:** Rebuild only when Clawith's base runner image changes major version. No Clawith Python source is patched.

***
### 5.2 Runner Shim
**What:** A lightweight Python process (~200 lines) that runs inside the sandbox, receives agent job payloads from the Clawith Orchestrator, executes one agent step, and streams results back. It is the only component that knows Clawith's workspace path layout.

**Why:** Clawith's backend worker currently executes agents directly. The shim replaces direct execution with sandboxed execution while keeping all scheduling and dispatch logic in Clawith's unchanged control plane.

**Interface contract:**

```python
# Input — delivered via stdin or Unix socket
{
  "agent_id": "uuid",
  "task_id": "uuid",
  "workspace_path": "/workspace/<task-id>/",  # only writable mount
  "soul_path": "/mnt/soul/soul.md",           # read-only
  "memory_path": "/mnt/memory/memory.md",     # read-only
  "job_type": "chat | cron | webhook | poll",
  "payload": { ... }
}

# Output — streamed back to Orchestrator
{
  "agent_id": "uuid",
  "task_id": "uuid",
  "events": [ { "type": "token|tool_call|result|error", "data": ... } ],
  "exit_code": 0
}
```

**Workspace path contract** (stable Clawith documented layout): [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)
- `backend/agent_data/<agent-id>/soul.md` → mounted read-only at `/mnt/soul/soul.md`
- `backend/agent_data/<agent-id>/memory.md` → mounted read-only at `/mnt/memory/memory.md`
- `backend/agent_data/<agent-id>/skills/` → mounted read-only at `/mnt/skills/`
- `backend/agent_data/<agent-id>/workspace/<task-id>/` → mounted read-write at `/workspace/<task-id>/`

If Clawith renames these paths in a future version, only the path strings in the shim's configuration need updating — not any business logic.

***
### 5.3 Agent Sandbox Registry
**What:** One new database table in Clawith's PostgreSQL, managed by an Alembic migration.

**Schema:**

```sql
CREATE TABLE agent_sandboxes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL UNIQUE REFERENCES agents(id) ON DELETE CASCADE,
    sandbox_name    TEXT NOT NULL,
    gateway_host    TEXT NOT NULL DEFAULT 'localhost',
    status          TEXT NOT NULL DEFAULT 'pending',
      -- pending | creating | running | stopped | error
    policy_hash     TEXT,          -- SHA256 of last applied policy.yaml
    provider_hash   TEXT,          -- SHA256 of last applied provider bundle
    image_tag       TEXT NOT NULL, -- pinned image digest
    openshell_ver   TEXT NOT NULL, -- pinned OpenShell version
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now()
);
```

**Why:** Enables idempotent sandbox lifecycle management. Orchestrator checks this table before creating a new sandbox to avoid duplicates. Stores policy and provider hashes for drift detection. Records the pinned OpenShell version so upgrades are deliberate migration events.

***
### 5.4 Sandbox Orchestrator
**What:** A Python service module (`backend/services/sandbox_orchestrator.py`, ~300 lines) wrapping the OpenShell Python SDK (`python/openshell/`).  This is the only component that talks to the OpenShell gateway.

**Public interface:**

```python
class SandboxOrchestrator:
    async def ensure_sandbox(self, agent_id: UUID) -> SandboxStatus
    async def start_sandbox(self, agent_id: UUID) -> None
    async def stop_sandbox(self, agent_id: UUID) -> None
    async def apply_policy(self, agent_id: UUID, policy: SandboxPolicy) -> None
    async def sync_providers(self, agent_id: UUID) -> None
    async def dispatch_job(self, agent_id: UUID, job: AgentJob) -> AsyncIterator[AgentEvent]
    async def get_status(self, agent_id: UUID) -> SandboxStatus
    async def stream_logs(self, agent_id: UUID) -> AsyncIterator[str]
```

**Implementation notes:**
- Uses OpenShell Python SDK: `openshell sandbox create`, `openshell policy set`, `openshell provider create`. 
- `ensure_sandbox` is idempotent: reads from `agent_sandboxes` registry, creates only if not running.
- `apply_policy` computes SHA256 of policy YAML, skips if hash matches stored `policy_hash`.
- `dispatch_job` passes job payload to the Runner Shim inside the sandbox via SSH or Unix socket.
- All gateway calls time out after 30 seconds with structured error logging.

***
### 5.5 Policy Compiler
**What:** A function that converts Clawith agent configuration into an OpenShell policy YAML document. This is the core of the inverted security model — security decisions are encoded here, not in Clawith's code.

**Input (from Clawith agent model):**

```python
@dataclass
class AgentPolicyInput:
    agent_id: UUID
    org_id: UUID
    approved_mcp_servers: list[str]      # from MCP registry
    approved_channel_endpoints: list[ChannelEndpoint]  # from approval queue
    approved_trigger_urls: list[str]     # from approval queue
    model_provider: str                  # e.g. "anthropic", "openai"
    allow_code_execution: bool
    allow_web_access: bool
```

**Output (OpenShell policy YAML structure):**

```yaml
# Generated by Clawith Policy Compiler v1
# agent_id: <uuid>  policy_hash: <sha256>

filesystem:
  allow:
    - path: /workspace/<task-id>/
      access: read-write
    - path: /mnt/soul/soul.md
      access: read
    - path: /mnt/memory/memory.md
      access: read
    - path: /mnt/skills/
      access: read
    - path: /tmp/
      access: read-write
  deny:
    - path: /
      access: read-write  # default deny everything else

process:
  allow:
    - binary: /opt/clawith-shim/entrypoint.sh
    - binary: /usr/local/bin/python3
    - binary: /usr/local/bin/node
    # explicitly no smithery, no modelscope, no pip install
  deny:
    - syscalls: [ptrace, mount, clone_newns]

network:
  default: deny
  allow:
    # Inference — handled by inference router below, not raw HTTP
    # MCP servers — from approved registry only
    - host: <mcp-server-1-host>
      methods: [POST]
      paths: ["/mcp"]
    # Channel endpoints — path-scoped, not wildcard
    - host: slack.com
      methods: [POST]
      paths: ["/api/chat.postMessage"]
      # channel_id enforced at DLP layer
    - host: discord.com
      methods: [POST]
      paths: ["/api/webhooks/<approved-webhook-id>"]
    # Trigger poll targets — from approval queue only
    - host: <approved-poll-target>
      methods: [GET]
      paths: [<approved-path>]
  deny:
    - host: "*"   # everything else

inference:
  route:
    - match: host: api.anthropic.com
      action: proxy
      strip_caller_credentials: true
      inject_provider: clawith-anthropic-provider
    - match: host: api.openai.com
      action: proxy
      strip_caller_credentials: true
      inject_provider: clawith-openai-provider
```

**Key policy rules derived from Clawith's attack surface:**

1. **No wildcard network access** — every allowed host is explicit. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)
2. **Channel endpoints are path-scoped** — `POST /api/chat.postMessage` only, not `slack.com/*`. A prompt-injected agent cannot call `slack.com/api/files.upload` or `slack.com/api/users.list`. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)
3. **Inference is always routed** — the agent never holds model API credentials. 
4. **MCP servers are allowlisted** — the agent cannot connect to unapproved MCP servers. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)
5. **Trigger poll targets are individually approved** — each external URL must appear in the Approval Queue before it is added to the policy. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)

***
### 5.6 Provider Sync Service
**What:** Maps Clawith's configured model/API secrets into OpenShell provider objects, injected at sandbox creation rather than stored in the sandbox filesystem. 

**Implementation:**

```python
class ProviderSyncService:
    async def sync(self, agent_id: UUID, org_id: UUID) -> str:
        """Create or update OpenShell provider bundle. Returns provider hash."""
        config = await self.get_org_provider_config(org_id)
        # Call openshell provider create for each active provider
        # Credentials come from Clawith's secrets store, never written to sandbox FS
        for provider in config.active_providers:
            await self.openshell.provider_create(
                name=f"clawith-{provider.name}-{org_id}",
                type=provider.type,
                credentials=provider.credentials,  # injected at runtime only
            )
        return compute_hash(config)
```

**Maintenance:** Rerun on API key rotation. No sandbox rebuild needed — providers are hot-injectable. 

***
### 5.7 DLP Gate
**What:** A server-side output scanner that intercepts all agent results before they reach Clawith's API response layer or channel delivery functions.

**Why:** OpenShell's network policy enforces at host/method/path level but cannot inspect message content.  A prompt-injected agent posting to an approved Slack path can still exfiltrate `soul.md` content in the message body. The DLP gate closes this gap. It runs in the Clawith control plane, not inside the sandbox, and is therefore not subject to sandbox compromise. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)

**Implementation:**

```python
class DLPGate:
    PATTERNS = [
        r"sk-[A-Za-z0-9]{32,}",          # OpenAI-style keys
        r"ANTHROPIC_API_KEY=\S+",
        r"-----BEGIN (RSA|EC) PRIVATE KEY",
        r"[A-Za-z0-9+/]{64,}={0,2}",     # high-entropy base64
    ]
    IDENTITY_FILES = ["soul.md", "memory.md"]

    async def scan(self, agent_id: UUID, output: AgentOutput) -> ScanResult:
        for channel_payload in output.channel_messages:
            for pattern in self.PATTERNS:
                if re.search(pattern, channel_payload.content):
                    return ScanResult(action="hold", reason="secret_pattern")
            if self._matches_identity_file(agent_id, channel_payload.content):
                return ScanResult(action="hold", reason="identity_content")
        return ScanResult(action="allow")

    def _matches_identity_file(self, agent_id, content):
        # Fingerprint soul.md and memory.md at rest;
        # check if output content has high token overlap with fingerprint
        ...
```

Held outputs go into Clawith's existing Approval Queue. Org admins review and release or discard. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)

***
### 5.8 MCP Registry
**What:** A new database table listing pre-approved MCP server endpoints per org. The Policy Compiler reads from this table to generate the network allowlist. The Runner Shim resolves MCP connections only to approved entries.

**Schema:**

```sql
CREATE TABLE mcp_registry (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES organizations(id),
    name         TEXT NOT NULL,
    url          TEXT NOT NULL,
    allowed_tools JSONB,  -- null = all tools; array = specific tool names only
    approved_by  UUID REFERENCES users(id),
    approved_at  TIMESTAMPTZ,
    status       TEXT DEFAULT 'pending',
    UNIQUE(org_id, url)
);
```

New MCP servers requested by agents go into the Approval Queue. Once approved, the Policy Compiler regenerates the agent's network policy (hot-reloadable) to include the new host. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)

***
### 5.9 Trigger Approval Extension
**What:** An extension to Clawith's existing Approval Queue that intercepts `poll`, `webhook`, and `interval` trigger creation when they specify external URLs.

**Why:** Self-created poll/webhook triggers are persistent durable exfiltration channels that survive across sessions.  This is the highest-severity vector unique to Clawith's architecture that NemoClaw does not face (NemoClaw has no self-created external trigger system). [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)

**Behaviour change:**

- `cron`, `once` triggers with no external URL: no change, activate immediately.
- `poll`, `webhook`, `interval` triggers with an external URL: status set to `pending_approval`, trigger not activated, org-admin notified.
- On approval: URL is added to the agent's OpenShell network policy via hot-reload (`openshell policy set`), then trigger is activated.
- On rejection: trigger deleted, agent receives a denied event.

This can be implemented as a single middleware on the trigger creation endpoint in Clawith's trigger module, checking `trigger_type` and `target_url` fields. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)

***
## 6. What is not built (and why)
| Skipped item | Reason |
|---|---|
| Patching Clawith's tools engine code | Smithery/ModelScope removed at image layer — no code patch needed |
| Patching Clawith's MCP client code | OpenShell network policy denies unapproved MCP hosts — no code patch needed |
| Patching Clawith's channel delivery code | OpenShell path-scoped network policy blocks non-approved endpoints — DLP gate handles content |
| Per-org OpenShell gateways (Phase 1) | OpenShell is still alpha single-player mode; use one gateway per deployment initially |
| GPU policy | Only needed if local inference is required; add later via `openshell sandbox create --gpu` |

***
## 7. Security equivalence to NemoClaw
| Vector | NemoClaw | This proposal |
|---|---|---|
| Runtime tool install | ✅ Single runtime, no install surface | ✅ Smithery/ModelScope removed from image |
| Credential leakage | ✅ Provider injection, no FS creds | ✅ Same via Provider Sync |
| Inference interception | ✅ OpenShell inference router | ✅ Same |
| Filesystem scope | ✅ `/sandbox` + `/tmp` only | ✅ Split mounts, identity files read-only |
| Network default-deny | ✅ OpenShell policy | ✅ Same |
| Unlisted host approval | ✅ TUI operator approval | ✅ Clawith Approval Queue + hot-reload |
| Channel exfiltration | ⚠️ Fewer channels, similar risk | ✅ Path-scoped + DLP gate |
| Durable trigger beacons | ✅ No self-created triggers | ✅ Trigger Approval Extension |
| MCP expansion | ✅ No MCP client | ✅ MCP Registry allowlist |
| Multi-tenant isolation | N/A (single-user) | ✅ Per-agent sandboxes + RBAC |
| Audit trail | ⚠️ TUI/logs only | ✅ OCSF events bridged to Clawith DB |

 [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)

***
## 8. Build order for a coding agent
Execute in this exact sequence. Each phase is independently deployable and testable.

**Phase 1 — Foundation (no user-facing changes)**

1. Write Alembic migration for `agent_sandboxes` table
2. Write Alembic migration for `mcp_registry` table
3. Implement `SandboxOrchestrator` wrapper (stub OpenShell calls first with `OPENSHELL_STUB=1`)
4. Implement `PolicyCompiler` → produces valid YAML from hardcoded test agent config
5. Implement `ProviderSyncService` → syncs to OpenShell provider API
6. Add `execution_mode` config flag: `local` (existing) or `openshell` (new path), default `local`

**Phase 2 — Sandbox image and shim**

7. Write hardened `Dockerfile` (derive from OpenShell community image, remove Smithery/ModelScope, install Runner Shim)
8. Implement `runner_shim` entrypoint and job/result protocol
9. Wire `SandboxOrchestrator.dispatch_job` to Runner Shim via SSH
10. Write `OPENSHELL_STUB` fake sandbox that runs Runner Shim locally for unit tests

**Phase 3 — DLP and trigger approval**

11. Implement `DLPGate` with pattern scanner and identity fingerprinting
12. Wire DLP Gate into Clawith's agent output path (before channel delivery)
13. Extend Approval Queue model with `trigger_approval` and `mcp_approval` entry types
14. Add trigger creation middleware: intercept external-URL triggers, set `pending_approval`
15. Add policy hot-reload call on trigger approval: `openshell policy set <sandbox> --policy <updated>`

**Phase 4 — Integration and flip**

16. End-to-end test: create agent, set `execution_mode=openshell`, run chat job, verify policy enforcement
17. Verify DLP gate blocks `soul.md` content in Slack messages
18. Verify trigger approval blocks unapproved poll targets at network layer
19. Verify MCP registry blocks unapproved MCP servers
20. Flip `execution_mode` default to `openshell`

***
## 9. Dependency versions to pin
| Dependency | Version to pin | Source |
|---|---|---|
| OpenShell | `v0.0.25` (latest stable as of 2026-04-08) | [github.com/NVIDIA/OpenShell releases](https://github.com/NVIDIA/OpenShell) |
| OpenShell Python SDK | same as above via `uv tool install openshell==0.0.25` |  |
| OpenShell community sandbox base | pin image digest in Dockerfile | `ghcr.io/nvidia/openshell-community/openclaw@sha256:...` |
| NemoClaw blueprint reference | `v*` latest tag | [github.com/NVIDIA/NemoClaw](https://github.com/NVIDIA/NemoClaw) |

Treat OpenShell version upgrades as **planned migration events**: bump pin, re-verify policy schema, re-test, then deploy. Never auto-update OpenShell. 

***
## 10. What is explicitly out of scope
- Multi-tenant OpenShell gateways (one gateway per deployment is sufficient for Phase 1)
- GPU passthrough (add later with `--gpu` flag)
- NemoClaw's Telegram bridge
- VLA/ROS integration (ROSClaw concern, not Clawith)
- OpenClaw source compatibility (Clawith shares no code with OpenClaw) [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/545755/3f3a6220-62e0-4f5d-97da-4e87d573a71c/CHANGELOG.md)