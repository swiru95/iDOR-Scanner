---
name: idor-scan
description: Run a multi-user IDOR/BOLA authorization scan with iDOR-Scanner. Use when the user wants to test broken object-level authorization across user roles against a running API — from a plain-English target description, an OpenAPI spec, or Burp proxy history. Builds the config, runs idor_scanner.py, and triages findings. Trigger on "scan for IDOR", "test authorization", "BOLA test", "check access control across users", "run the idor scanner".
---

# idor-scan

End-to-end IDOR/BOLA testing with the project's `idor_scanner.py`. You build a config, run the scanner, and triage the findings for the user during a pentest.

The scanner is deterministic at its core: it authenticates every user, fires each request as every user (plus an anonymous request) concurrently, and compares HTTP status/body against a declared allow-list. An optional local Ollama layer adds login-sequence generation, per-finding response analysis, and report summarisation.

## Workflow

1. **Gather inputs.** Determine the target, the user roles + credentials, and which input mode applies (see below). If credentials or the target base URL are missing, ask the user — never invent them.
2. **Write a config file.** YAML (`.yaml`/`.yml`, needs PyYAML) or JSON (`.json`, zero deps). Put it somewhere sensible like `./scan-config.yaml`. Mirror the structure in `example/ci_flask_demo_config.yaml`.
3. **Auto-detect Ollama** (see LLM section). Only wire it in if a local Ollama is reachable.
4. **Run** `python3 idor_scanner.py --config <cfg> --output report.json --output-sarif report.sarif`.
5. **Triage.** Read `report.json`, summarise high/medium findings, and distinguish real broken-access from stateful-data noise. Report the exit code (1 = high-risk finding present).

## Config essentials

```yaml
http_timeout_seconds: 20          # optional, default 20
max_concurrent_requests: 5        # optional
users:
- name: alice
  variables: {username: alice, password: alice-pass}   # used in login_sequence templates
  # OR, if you already hold tokens and skip login_sequence:
  # headers: {Authorization: "Bearer <token>"}          # applied to every request for this user
login_sequence:                   # omit if users carry static headers, or let Ollama/regex derive it
- request: {method: POST, url: https://target/api/login, json: {username: '{{username}}', password: '{{password}}'}}
  extract:
    access_token: {from: json, path: token}
authorization_tests:
- name: read-account-1001
  request:
    method: GET
    url: https://target/api/accounts/1001
    headers: {Authorization: "Bearer {{access_token}}"}
  expectations:
    allowed_users: [alice]        # who SHOULD have access; everything else is a finding
```

**Templating:** `{{var}}` resolves from a user's `variables`, anything `extract`ed during login, or `{{env.NAME}}`. Rendered across URL, headers, and body.

**`extract` modes** (pull a value out of a login response into the user's context):
- `{from: json, path: token}` — JSON field by dot-path
- `{from: header, name: Location, pattern: "code=([a-f0-9\\-]+)"}` — header value, optional regex capture group 1
- `{from: set_cookie, name: session}` — a named cookie from `Set-Cookie`
- `{from: regex, pattern: "..."}` — regex capture group 1 from the body

**Always prefer `expectations.allowed_users`** — it gives precise per-endpoint verdicts. Without it the scanner falls back to heuristics (identical bodies across users → medium; all-success different bodies → medium).

The scanner auto-tests every endpoint **unauthenticated** too — no config needed — so unprotected endpoints surface automatically.

## Input modes

**Plain-English target + creds:** Hand-write `login_sequence` from what the user describes (it's usually a single POST). If the login flow is multi-step/OAuth and Ollama is available, instead set `instruction_prompt` describing the flow and omit `login_sequence` — Ollama synthesises it (regex fallback otherwise). For multi-step flows you understand, just write the steps explicitly (see `example/oidc-http/oidc_config.yaml`).

**OpenAPI spec:** Set `openapi_spec_path: /abs/path/to/openapi.json` (or inline `openapi_spec`) and omit `authorization_tests` — one test is generated per operation. Tune with:
- `openapi_path_param_defaults: {id: 1}` / `openapi_operation_path_param_defaults`
- `openapi_expectation_overrides: {getAccount: [alice]}` — declare allow-lists per operationId
- `openapi_exclude_operation_ids: [login]` — skip auth endpoints
Still provide `users` and a way to auth (login_sequence / headers / instruction_prompt).

**Burp history / MCP:** For an exported history, list raw requests under `burp_history_requests: [{method, url, headers, body}, ...]`; each becomes a test with `Authorization: Bearer {{access_token}}` injected. For **live Burp**, set `burp_mcp_url: http://localhost:8081/mcp/request` so all scanner traffic routes through Burp (auto-detects MCP SSE vs legacy HTTP), and use `burp_mcp_history_requests` for live history. Use only one OpenAPI source and one Burp history source.

## Ollama (optional, auto-detect)

Probe first: `curl -s http://localhost:11434/api/tags`. Only if it responds, add `ollama_url: http://localhost:11434` and `ollama_model: <model>` to the config. That enables login-sequence generation (when `login_sequence` absent) and report summarisation. Add `llm_analyze_responses: true` to get a per-finding second-opinion verdict (`confirmed_idor`/`likely_idor`/`possible_idor`/`false_positive`/`clean`). For internal TLS Ollama, set `ollama_ca_bundle_path`. If Ollama is not reachable, proceed deterministic-only — do not block the scan.

## Running

Use the installed `idor-scanner` command if it's on PATH (`command -v idor-scanner`); otherwise run the script from the repo root with `python3 idor_scanner.py`. Flags are identical.

```bash
idor-scanner --config scan-config.yaml --output report.json --output-sarif report.sarif
# fallback: python3 idor_scanner.py --config scan-config.yaml --output report.json --output-sarif report.sarif
echo "exit: $?"   # 1 = at least one high-risk finding
```
- `--instruction "..."` overrides/supplies `instruction_prompt` from the CLI.
- YAML configs need PyYAML. Installed via `pipx install '.[yaml]'`; standalone via `pip install pyyaml`. JSON needs nothing beyond stdlib.

## Triage guidance

Read `report.json` and report concisely:
- **high — `possible_idor_or_broken_access_control`**: a non-allowed user (or anonymous) got 2xx, or an allowed user got 401/403. These are the real findings — call them out with endpoint + which user.
- **medium — `possible_stateful_test_or_missing_fixture`**: allowed user got 404/410. Usually missing test data, not a bug — note but don't alarm.
- **medium heuristics** (`possible_idor_identical_successful_access`, `possible_cross_user_data_leak`): no allow-list was declared; recommend adding `expectations.allowed_users` to confirm.
- If `llm_analysis`/`llm_summary` present, treat it as a second opinion — the deterministic verdict is authoritative.

Verify a finding before calling it confirmed: check the actual per-user statuses/body previews in the report rather than trusting the label alone.
