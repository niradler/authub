# authub — project instructions

authub is an open-source (MIT) typed, composable authentication hub for FastAPI: OAuth2/OIDC/SAML SP,
user+service JWTs, pluggable stores/email/plugins, and an embedded OIDC IdP (`authub.idp.AuthubIdp`).

## The plan is the source of truth

`docs/superpowers/plans/2026-06-10-authub-v1.md` contains the complete v0.1 implementation plan:

- **Section 0 (Decisions D1–D27)**: every open design question is CLOSED there. Do not re-litigate,
  do not "improve" a decision mid-task. If a decision proves impossible in practice, stop and surface it.
- **Validated API facts** (end of section 0): joserfc/authlib/pysaml2 behaviors verified by running
  code — trust them over intuition (e.g. joserfc needs explicit `algorithms=["Ed25519"]`;
  `AsyncOAuth2Client.create_authorization_url` is sync while `fetch_token` must be awaited).
- Execute task-by-task (1 → 21), TDD: write the failing test, run it, implement, run, gate, commit.
- Track progress by checking off the `- [ ]` boxes in the plan file and updating
  `.claude/docs/authub-v1.md` after each completed task.

## Commands

```powershell
uv sync --dev --all-extras          # setup
uv run pytest -q                    # tests
uv run ruff format . ; uv run ruff check . ; uv run mypy ; uv run pytest -q   # full gate (before every commit)
uv build                            # wheel + sdist
```

Always pass explicit timeouts on shell commands. SAML tests skip on this Windows machine
(no xmlsec1 binary) — that is expected; CI covers them.

## Conventions

- Python ≥3.11, src layout, `from __future__ import annotations` in every file, absolute imports only.
- Pydantic v2 `BaseModel` on every boundary, `StrEnum`, `SecretStr` for secrets (never log/serialize them).
- Async everywhere; sync third-party work (pysaml2) via `asyncio.to_thread` behind a bounded semaphore.
- ruff (line-length 100, configured rule set) + mypy `--strict` must stay green; never weaken configs to pass.
- Tests: pytest `asyncio_mode=auto`, `httpx.AsyncClient` + `ASGITransport`, no network in tests.

## Hard rules

- Commits: conventional (`feat:`/`test:`/`chore:`), imperative. **NEVER add AI attribution of any
  kind** — no "Generated with Claude Code", no "Co-Authored-By: Claude", no emoji footers.
- Never publish to PyPI (`uv publish`) — Nir does that manually.
- `refs/` holds read-only reference checkouts for API
  shape only. **Never copy code from them** (licensing); never lint/format/commit them.
- Never suppress a failing test to go green; state root cause before fixing anything.
- Security review before marking a task done: no secret leaks, no open redirects, errors stay client-safe.
