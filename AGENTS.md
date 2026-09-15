# AGENTS.md — working in this repository as an AI coding agent

Read this first, then `README.md`, then the module docstring and test file for the area you are changing.

## What this repo is

A deployable AWS sample: MCP clients that use **CIMD** (URL `client_id`) sign users in through **Amazon Cognito**, which stays the token issuer. A thin serverless layer translates: `cimd-proxy` (authorization-server façade), `registrar` (creates one Cognito shadow app client per allow-listed CIMD URL), and a FastMCP resource server. CDK in TypeScript, Lambdas in Python 3.12.

## Map

| Path | What lives there |
|---|---|
| `config.ts` | every configurable value, validated at synth (`README.md` §9) |
| `bin/app.ts`, `lib/*.ts` | four stacks: userpool → data → api → registration; `lib/derive.ts` holds URL derivations and `validateConfig` |
| `lib/constructs/python-lambda.ts` | Docker-free bundling from `uv.lock` (`uv export` + `uv pip install --python-platform aarch64-manylinux2014`) |
| `lambdas/shared/` | `cimd_url.py` (client_id rules), `mapping_store.py` (read side), `runtime_config.py` (SSM, cached), `logging_setup.py` (redaction) |
| `lambdas/mcp_server/` | FastMCP app, `verifier.py` (`ScopedVerifier`: scope → 403, registered client → 401) |
| `lambdas/cimd_proxy/` | `proxy_app.py` router; `oauth.py` validation/errors/metadata; `freshness.py`; `consent.py`; `cognito_relay.py`; `test_client.py` |
| `lambdas/registrar/` | `fetcher.py` (SSRF guards), `validate.py`, `reconcile.py` (reaction matrix, `revalidate_one`), `cognito_ops.py`, `store.py` (lock, transactions), `handler.py` |
| `tests/unit/` (pytest), `tests/cdk/` (jest + cdk-nag) | the contract: each file states the behaviour it protects |

Do not add new top-level documentation folders; the README and the module docstrings are the documentation of record.

## Commands

```bash
npm ci && uv sync --all-groups          # tooling (Node 22, Python 3.12, uv 0.8+)
npm run build                           # tsc --noEmit
npx jest                                # CDK assertions + cdk-nag (must stay clean)
uv run pytest -q                        # Lambda unit tests, no AWS
uv run ruff check lambdas tests         # lint (line length 120)
npx cdk synth --quiet                   # validate config + templates
npx cdk diff <stack> --exclusively      # ALWAYS read before deploying
npx cdk deploy --all --require-approval never
```

Stack names are `<project.name>-<project.stage>-{userpool,data,api,registration}`. Deploy in that order when a change adds a cross-stack export (for example a new value passed from userpool to api); `--exclusively` skips dependencies, which is what you want for a one-stack code change and what breaks a new export.

## Invariants — do not break these

1. **`config.ts` is the single source.** No region, URL, host, ARN, resource name, lifetime or toggle anywhere else. Dependency versions live only in `pyproject.toml`/`uv.lock` and `package.json`. New tunable = `Config` interface + defaults + `validateConfig` + Lambda env in the stack + handler read + `README.md` §9.
2. **No URL in a Lambda environment variable.** Public URLs are written to SSM by `RegistrationStack` (the last stack) and read by `shared/runtime_config.py`. A CDK test fails if any env value contains `execute-api` or `cloudfront.net`. The one allowed host-shaped env var is `COGNITO_LOGIN_BASE_URL` (Cognito-owned, exists before the API).
3. **The proxy mints nothing and has no `cognito-idp:*` permission.** It maps `client_id` → shadow client id and forwards. Cognito verifies PKCE, matches `redirect_uri`, issues and revokes tokens.
4. **Only the registrar touches app clients.** Inputs come from `cimd.allowedClients`. Redirect URIs must be https (localhost clients are out of scope by design). Every mapping write is a `TransactWriteItems` so readers never see a half state.
5. **Fail closed.** `/authorize`, `/consent`, `/token` require an `enabled` mapping with `now < cache_until`, else a synchronous registrar `revalidate`; only `{status: ok, fresh: true, enabled: true}` authorizes. `locked`/`error`/timeout → `temporarily_unavailable` + `Retry-After`, never `invalid_client`. `fresh` means "validated by this call" (so no-cache/no-store documents still work).
6. **RFC 6749 validation order at `/authorize`.** Bad `client_id` or `redirect_uri` → 400 page, never a redirect. Everything after that → 302 to the validated `redirect_uri` with `error` and `state`. The proxy redirects only to Cognito's login domain or a registered `redirect_uri`.
7. **No secrets, no DCR, no MFA, no OIDC provider claims.** `/.well-known/openid-configuration` serves the same OAuth-only RFC 8414 document as a discovery fallback; ID tokens are Cognito's and carry the Cognito issuer (deliberate exception, stated in `lambdas/cimd_proxy/oauth.py`).
8. **Nothing sensitive in logs.** Use `shared.logging_setup.log(...)` with structured fields; the redaction list covers tokens, codes, `state`, cookies, `Authorization`. Never log a token to debug.
9. **Module names must not collide across Lambdas** in the shared pytest process (`app.py` belongs to `mcp_server`; the proxy's router is `proxy_app.py`).
10. **Defaults are production-safe:** `testClient`, `devFixtures`, `createDemoUsers`, `edge` are all off. Do not flip them in `config.ts` for a local experiment; use `CIMD_CONFIG_OVERRIDES`.

## Deployment overrides

`CIMD_CONFIG_OVERRIDES` (JSON, shallow-merged per top-level key at synth) carries environment-specific values: a mandatory permissions boundary, `testClient`, `devFixtures`. A deployment made with overrides must be updated with the same overrides, otherwise `cdk diff` shows removed roles' boundaries and destroyed fixtures. If `cdk diff` shows anything you did not intend, stop and reconcile the overrides first.

## When you change behaviour

- Change the test in the same commit. `tests/unit/test_proxy.py`, `test_reconcile.py`, `test_fetcher.py`, `test_validate.py`, `test_http_auth.py` each say what they protect.
- Update the module docstring that states the rule, and the relevant `README.md` section (§2 security table, §8 operations, §9 config reference) when behaviour visible to operators changes.
- Keep both suites green and `cdk-nag` clean. New IAM permissions or routes need a **scoped** suppression with a reason in `lib/nag-suppressions.ts`, never a blanket one.
- Verify live when you can: deploy the affected stack with `--exclusively`, download the function's package (`aws lambda get-function`) and grep for your change, then run the curl checks in `README.md` §7 or the built-in test client.

## Things that look like bugs but are decisions

- `authorizationServerUrl` ≠ `tokenIssuer`: the façade is ours, tokens are Cognito's. Do not "fix" the metadata to point `issuer` at Cognito.
- `openid` is accepted at `/authorize` but not advertised in `scopes_supported`.
- The MCP server returns 403 `insufficient_scope` for a valid token without the scope and 401 for an unregistered client; the scope check sits on the outer verifier for exactly this reason.
- Cognito redirects the code straight to the client; the proxy is not in the return path and holds no per-request state. This is why loopback/variable-port clients are unsupported and why RFC 9207 `iss` is not available.
- The registrar stores `cache_until = now` for `no-cache`/`no-store` documents and still reports `fresh: true` for the call that validated them.

## Don'ts

- Don't add Docker to the build, Secrets Manager to the default profile, a `$default` catch-all route, a Cognito client secret, or a DCR endpoint.
- Don't print or persist passwords/tokens while testing; create throwaway Cognito users, set passwords with `admin-set-user-password`, delete the user afterwards.
- Don't edit `cdk.out/`, `.venv/`, or `node_modules/`.
- Don't add a client identifier URL to `cimd.allowedClients` as a default. It ships empty so that a deploy trusts nobody; `KNOWN_CIMD_CLIENTS` in `config.ts` is reference data for an operator to copy from, not an allow-list.
