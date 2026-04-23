# Security Fixes — 2026-04-23

Implementation record for the four High-severity findings documented in [security-review-2026-04-23.md](security-review-2026-04-23.md). All fixes landed on branch `feat/security-fixes-2026-04-23`.

## Summary

| Finding | File(s) changed | Tests added | Status |
|---|---|---|---|
| 1 — Authenticated RCE via command injection | [backend/app/api/upload.py](../backend/app/api/upload.py) | 1 case | Closed |
| 2 — Path traversal / arbitrary file write | [backend/app/api/upload.py](../backend/app/api/upload.py) | 3 cases | Closed |
| 3 — Stored XSS in Markdown renderer | [frontend/src/components/MarkdownRenderer.tsx](../frontend/src/components/MarkdownRenderer.tsx), [frontend/package.json](../frontend/package.json) | Manual XSS suite | Closed |
| 4 — Cross-tenant IDOR → account takeover | [backend/app/api/organization.py](../backend/app/api/organization.py) | 5 cases | Closed (incl. same-tenant role-escalation variant) |

## Commits

| SHA | Subject |
|---|---|
| `8023850` | feat: implement security enhancements for file uploads and user role validation |
| `34306e0` | feat: enhance MarkdownRenderer to allow target and referrerpolicy attributes for improved security |
| `f978618` | test: update assertions in test_list_users_cross_tenant_filter for UUID comparison |

## Fix 1 — Authenticated RCE via command injection

**Root cause.** `extract_text()` in `upload.py` embedded the attacker-controlled upload filename inside a Python `-c` argument via f-string interpolation, making the filename executable.

**Fix.** Deleted the local `extract_text()` entirely. Office-format extraction (PDF/DOCX/XLSX/PPTX) now delegates to the existing shared helper `app.services.text_extractor.extract_text(content: bytes, filename: str)` — already used by [backend/app/api/files.py:289](../backend/app/api/files.py#L289). Text-format extraction decodes bytes in-process. No subprocess is spawned, no filename is ever parsed as code, and PPTX support comes for free.

**Tests.** `test_upload_security.py::test_injection_filename_does_not_execute_code` asserts that a filename crafted to break out of the old `-c` string literal produces no side-effect.

## Fix 2 — Path traversal / arbitrary file write

**Root cause.** `upload_file()` accepted `agent_id` as an unvalidated `Form("")` string and used the raw `UploadFile.filename` verbatim when building `save_path`. No `check_agent_access`, no containment check, no filename sanitization.

**Fix.** Rewritten handler:

- `agent_id: uuid.UUID = Form(...)` — required; FastAPI coerces and returns 422 on invalid input.
- `await check_agent_access(db, current_user, agent_id)` — same helper every `files.py` handler uses; 404 if unknown, 403 on cross-tenant.
- Filename sanitization: `os.path.basename` + `replace("/", "_").replace("\\", "_")`, reject empty / `.` / `..` / null-byte, truncate to 200 bytes.
- Path containment runs **before** any `mkdir`:
  ```python
  uploads_dir = (WORKSPACE_ROOT / str(agent_id) / "workspace" / "uploads").resolve()
  save_path = (uploads_dir / safe_name).resolve()
  if not str(save_path).startswith(str(uploads_dir) + os.sep):
      raise HTTPException(400, "Invalid path")
  uploads_dir.mkdir(parents=True, exist_ok=True)
  ```
- Collision handling uses `os.open(..., O_WRONLY | O_CREAT | O_EXCL)` inside an incrementing-suffix loop instead of a racy `path.exists() + write_bytes` pair.
- Removed the anonymous `/tmp/clawith_uploads` fallback branch (no remaining callers).

**Tests.** `test_path_traversal_filename_is_rejected_or_sanitized`, `test_invalid_agent_id_is_rejected_by_pydantic`, `test_cross_tenant_agent_access_returns_403`, `test_happy_path_text_upload`.

## Fix 3 — Stored XSS in Markdown renderer

**Root cause.** The hand-rolled Markdown parser passed user content through `dangerouslySetInnerHTML` with no escaping of raw HTML, no URL-scheme validation, and no sanitization of link/image attributes. JWTs in `localStorage` made every XSS instance a full session takeover primitive.

**Fix.** Two-layer defense — URL scheme whitelist at parse time, DOMPurify sanitization on the final HTML:

- Added `dompurify@^3.2.0` to [frontend/package.json](../frontend/package.json). `@types/dompurify` was intentionally **not** added — types ship with `dompurify@3.2.x` and the standalone types package is deprecated.
- New `isSafeUrl(raw)` helper normalizes (trim, strip `\t\n\r`, lowercase) then accepts only `http://`, `https://`, `mailto:`, `/` (but not `//`), `#`, or scheme-less relative URLs. Rejected URLs render as escaped plain text.
- Image and link handlers call `isSafeUrl` first and pass alt/text through the existing `escapeHtml()` before interpolation.
- **`/api/agents/*` images are no longer wrapped in an outbound `<a target="_blank">`.** The previous wrapper caused the attached `?token=<JWT>` to leak via `Referer` on click-through and via browser URL bar / history. Agent images now render as bare `<img>` with `referrerpolicy="no-referrer"`. External images keep the outbound wrapper with `rel="noopener noreferrer"`.
- Final HTML is passed through:
  ```ts
  DOMPurify.sanitize(html, {
      USE_PROFILES: { html: true },
      ADD_ATTR: ['target', 'referrerpolicy'],
  })
  ```
  The `ADD_ATTR` entries are required — DOMPurify strips `target` and `referrerpolicy` by default, which would silently defeat both the outbound-link behavior and the no-referrer hardening.

**Smoke tests performed.**
- CSS custom properties (`var(--bg-secondary)`, `var(--accent-primary)`, `var(--border-color)`, `var(--text-secondary)`) survive sanitization in `style` attributes on every element the parser emits. The reviewer-flagged silent-regression risk does not materialize in DOMPurify 3.4.x.
- Payloads neutralized: `<img src=x onerror=…>`, `<svg onload=…>`, `<iframe src=javascript:…>`, `[x](javascript:…)` (any case), `[x](//evil.com)`, `[x](data:text/html,…)`, `![x](" onerror=… x=")`, entity-encoded `javascript:`, tab-stuffed `java\tscript:`.
- `npm run build` compiles cleanly.

## Fix 4 — Cross-tenant IDOR (and same-tenant role escalation)

**Root cause.** `PATCH /org/users/{user_id}` accepted both `platform_admin` and `org_admin` via `get_current_admin` but performed no tenant check on the target user and no role-hierarchy check. Mutable fields (`email`, `username`, `primary_mobile`) write through to the global `Identity` row, so an `org_admin` could PATCH any user in any tenant and chain to `/auth/forgot-password` → `/auth/reset-password` for full account takeover.

The review focused on the cross-tenant variant; reviewer flagged that the same-tenant variant (`org_admin` in tenant A taking over a `platform_admin` in tenant A) survives a tenant-only check.

**Fix.** Two-dimensional guard in `admin_update_user`, plus a tightening of `list_users`.

`list_users`:
```python
if current_user.role == "platform_admin" and tenant_id:
    target_tenant_id = tenant_id
```
(Previously also permitted `org_admin` to set `target_tenant_id`, enabling cross-tenant enumeration.)

`admin_update_user` (after loading `user`, before mutation):
```python
ROLE_RANK = {"member": 0, "agent_admin": 0, "user": 0,
             "org_admin": 1, "platform_admin": 2}

if current_user.role != "platform_admin":
    if user.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    if (ROLE_RANK.get(user.role, 0) >= ROLE_RANK.get(current_user.role, 0)
            and user.id != current_user.id):
        raise HTTPException(status_code=403, detail="Forbidden")
```

The `user.id != current_user.id` carve-out lets an `org_admin` edit their own profile. Status is **403** to match codebase convention ([users.py:122](../backend/app/api/users.py#L122), [files.py:52](../backend/app/api/files.py#L52), `permissions.py` 36/52) rather than the 404 originally drafted in the plan.

**Tests.** `test_org_admin_cross_tenant_patch_is_forbidden`, `test_org_admin_cannot_escalate_same_tenant_platform_admin`, `test_org_admin_can_patch_regular_user_in_own_tenant`, `test_platform_admin_can_patch_across_tenants`, `test_list_users_cross_tenant_filter_denied_for_org_admin`.

## Running the test suite

System default `python3` on this host inherits a ROS `PYTHONPATH` that breaks pytest collection. Use an isolated Python 3.11 matching the project's declared `requires-python`:

```bash
cd backend
env -u PYTHONPATH -u AMENT_PREFIX_PATH \
    uv run --isolated --python 3.11 --with pytest --with pytest-asyncio \
    python -m pytest tests/test_upload_security.py tests/test_organization_security.py -v
```

Expected: `10 passed`.

## Items intentionally deferred (follow-up work)

1. **Replace the hand-rolled Markdown parser with `react-markdown` + `rehype-sanitize`.** The parser has pre-existing correctness gaps (nested emphasis, escape handling inside code spans, table alignment) that DOMPurify does not fix. A library swap is the superior long-term answer but carries roughly 4× the effort of the DOMPurify patch.
2. **Move `/api/agents/*` download authentication off the query string.** The current fix adds `referrerpolicy="no-referrer"` and removes the outbound wrapper, closing the most obvious leak paths, but appending `?token=<JWT>` to URLs still surfaces the token in browser history, DevTools network panels, and request-logging middleware. A cookie-based or `Authorization`-header fetch-and-blob wrapper is the durable fix.
3. **Disable `/auth/forgot-password` in SSO-only deployments.** Fix 4 breaks the takeover chain at the IDOR layer so this is no longer required to close the finding, but when SSO is configured as the sole login mechanism the local reset flow is a parallel authentication path that bypasses MFA.
4. **Remove Identity-level fields (`email`, `username`, `primary_mobile`) from the tenant admin endpoint entirely.** They govern global authentication, not tenant-scoped profile state, and belong behind platform-admin-only controls or a dedicated `/auth/identity/*` namespace.

## Operator note

The branch is already pushed to `origin/feat/security-fixes-2026-04-23`.
