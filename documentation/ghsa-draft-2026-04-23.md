# GHSA Draft — `dataelement/Clawith` — 2026-04-23

Accelerated coordinated-disclosure draft for the four High-severity vulnerabilities fixed on branch `feat/security-fixes-2026-04-23`. Paste into the GitHub Security Advisory form on `dataelement/Clawith`, or submit via `gh api` using the filing command at the bottom. Do not open a public issue or PR that references these findings before maintainers greenlight.

## Filing form fields

| Field | Value |
|---|---|
| Package ecosystem | `Other` |
| Package name | `clawith` |
| Affected versions | `< 4474393` (upstream HEAD pre-fix; adjust to the released tag if one is cut) |
| Patched versions | *(leave empty — maintainer fills at release)* |
| Severity | **High** (CVSS 8.8 for Vuln 1; 8.1 for Vuln 2; 7.5 for Vuln 3; 7.5 for Vuln 4) |
| CWEs | `CWE-78`, `CWE-22`, `CWE-79`, `CWE-639` |
| Credits | per reporter's organizational clearance — default: route via CSIRT / security team as reporter, technical contact as named individual |
| Requested disclosure window | **14 days** from maintainer acknowledgment |

---

## Title

Multiple high-severity vulnerabilities: authenticated RCE, path traversal, stored XSS, cross-tenant account takeover

## Summary

Clawith contains four independent high-severity vulnerabilities affecting file uploads, markdown rendering, and organization-user administration. Combined, an authenticated user can obtain a backend shell, and an `org_admin` can take over any other tenant's account including `platform_admin`.

## Description

### Disclosure note

A technical write-up of these findings and working test cases are already published on a public GitHub fork (`hafnium49/Clawith`, branch `feat/security-fixes-2026-04-23`) as a consequence of premature in-public development of the fixes. The embargo window is therefore effectively already open. We recommend a **14-day coordinated-disclosure window** to allow upstream patching and downstream notification before the findings reach wider discovery. Patches are available as `git format-patch` attachments (see below) or via the temporary private fork this advisory will generate upon collaboration acceptance.

---

### Finding 1 — Authenticated RCE via command injection in `/chat/upload` (CWE-78)

- **Severity:** High
- **CVSS:** 8.8 (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`)

`backend/app/api/upload.py::extract_text()` previously constructed a Python program via f-string interpolation of an attacker-controlled `UploadFile.filename` and executed it via `subprocess.run(["python3", "-c", ...])`. Although invoked with `shell=False`, a filename containing a single quote breaks out of the inner Python string literal and yields arbitrary code execution on the backend process.

**Impact.** Any authenticated user uploads a crafted filename → full RCE on the backend → JWT secret disclosure, Postgres contents (all tenants), provider API keys.

**Fix.** Replace the subprocess+f-string extractor with in-process calls to the canonical extractor already in `app.services.text_extractor.extract_text(content: bytes, filename: str)`. Sanitize filenames (basename, slash/backslash replacement, null-byte rejection, length truncation).

---

### Finding 2 — Path traversal / arbitrary file write in `/chat/upload` (CWE-22)

- **Severity:** High
- **CVSS:** 8.1

`upload_file()` accepted `agent_id` as an unvalidated `Form("")` string and used `UploadFile.filename` verbatim when building the write path. No `check_agent_access`, no resolve-containment check, no filename sanitization. `pathlib` does not normalize `..` segments or absolute paths, yielding arbitrary write as the backend user anywhere it has permission.

**Impact.** Any authenticated user writes attacker-controlled bytes outside the agent workspace. Enables cross-tenant data poisoning, overwriting sensitive files, and (chained with Finding 1) RCE without needing a valid agent ID.

**Fix.** Parse `agent_id` as `uuid.UUID`, call `check_agent_access`, resolve path then assert containment against `uploads_dir.resolve()`, mkdir only after containment, sanitize filename, use `O_EXCL` for collision handling.

---

### Finding 3 — Stored XSS in `MarkdownRenderer` (CWE-79)

- **Severity:** High
- **CVSS:** 7.5

`frontend/src/components/MarkdownRenderer.tsx` passed user content through `dangerouslySetInnerHTML` via a hand-rolled parser that did not escape raw HTML runs, validate URL schemes, or sanitize link/image attributes. Combined with JWTs kept in `localStorage`, any XSS instance yields full session takeover. Exploitable via chat content, shared `.md` workspace files, and IM-integration ingestion (Feishu, WeCom, Slack, Discord).

**Fix.** Add `dompurify` dependency. Wrap the output in:

```ts
DOMPurify.sanitize(html, {
    USE_PROFILES: { html: true },
    ADD_ATTR: ['target', 'referrerpolicy'],
})
```

Add a URL-scheme allowlist rejecting `javascript:`, `data:`, `vbscript:`, protocol-relative `//…`, and tab/whitespace-stuffed variants. Stop wrapping `/api/agents/*` images in an outbound `<a target="_blank">` (Referer-leak of JWT); add `referrerpolicy="no-referrer"`.

---

### Finding 4 — Cross-tenant / cross-role IDOR on `PATCH /org/users/{id}` (CWE-639)

- **Severity:** High
- **CVSS:** 7.5

`backend/app/api/organization.py::admin_update_user` is guarded by `get_current_admin` (accepts both `org_admin` and `platform_admin`) but performs no tenant check and no role-hierarchy check. The mutable fields (`email`, `username`, `primary_mobile`) are `association_proxy` attributes that write through to the globally-unique `Identity` row. An `org_admin` in any tenant can PATCH any user's Identity email → call `/auth/forgot-password` → take over the target account, including `platform_admin` in the same or another tenant. `list_users?tenant_id=<other>` also permitted cross-tenant enumeration.

**Fix.** In `admin_update_user`, enforce tenant equality AND a role-rank check (non-`platform_admin` cannot PATCH a user whose role rank is ≥ their own, except self). In `list_users`, restrict the `tenant_id` override to `platform_admin` only. Return 403 per codebase convention.

---

## Patches

Available as `git format-patch` attachments when the advisory collaboration channel opens:

- `0001-fix-upload-prevent-RCE-via-command-injection.patch` — upload.py + test
- `0002-fix-upload-prevent-path-traversal.patch` — upload.py + test
- `0003-fix-markdown-sanitize-output-and-URL-schemes.patch` — MarkdownRenderer.tsx + package.json
- `0004-fix-organization-enforce-tenant-and-role-checks.patch` — organization.py + test

All patches include regression tests. Ten tests pass under:

```bash
env -u PYTHONPATH -u AMENT_PREFIX_PATH \
    uv run --isolated --python 3.11 --with pytest --with pytest-asyncio \
    python -m pytest tests/test_upload_security.py tests/test_organization_security.py -v
```

Expected: `10 passed`.

## Reporter

*(per Phase 0.5 clearance — fill before submission)*

## Requested timeline

**14 days** from advisory acknowledgment to coordinated publication. Broken-window clause: if any third party independently discloses, embargo lifts immediately.

---

## Filing command

After organizational clearance, and once the four patches are exported:

```bash
# Export the four patches from the fix branch
git format-patch -4 feat/security-fixes-2026-04-23 -o /tmp/clawith-patches/

# File the advisory (draft visible only to you and maintainers)
gh api -X POST /repos/dataelement/Clawith/security-advisories \
    --input /tmp/advisory.json
```

`/tmp/advisory.json` should be a JSON object with `summary`, `description` (full markdown above), `severity: "high"`, `cwe_ids`, `vulnerabilities`, and `credits` fields. Produce with `jq` from this markdown or hand-assemble.

Do NOT attach patches to the initial draft advisory — wait for maintainer acceptance + the temporary private fork, then push the patches there.
