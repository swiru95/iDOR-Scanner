# iDOR-Scanner
Repository that aims to help with iDOR detection supported by AI.

## Autonomous scanner

This repository now includes an autonomous CLI scanner:

- consumes a JSON configuration that can describe a login/authentication sequence or per-user request headers,
- can derive the initial login sequence from a natural-language instruction prompt,
- authenticates **N users** and extracts tokens from responses,
- executes authorization test requests (direct HTTP or via `burp_mcp_url`),
- compares response status/body patterns and reports potential iDOR findings,
- can optionally request a final summary from an Ollama model (`ollama_url` + `ollama_model`).

Request timeout can be tuned with `http_timeout_seconds` (defaults to `20`).
For internal TLS endpoints, set `ollama_ca_bundle_path` to a PEM bundle trusted for `ollama_url`.

Run:

```bash
python idor_scanner.py --config /absolute/path/to/config.json
```

Relative paths also work, for example:

```bash
python idor_scanner.py --config config.json
```

Prompt override is also supported:

```bash
python idor_scanner.py --config config.json --instruction "go to login.example.com and obtain token for app.example.com use these 3 users"
```

### Prompt-driven defaults

If `instruction_prompt` is present and `login_sequence` is missing, the scanner derives a login step automatically.
If `authorization_tests` is missing and `openapi_spec` or `openapi_spec_path` is provided, tests are derived from OpenAPI operations first.
If `authorization_tests` is missing and no OpenAPI source is provided, `burp_history_requests` (or `burp_mcp_history_requests`) is used and tests are derived from those requests with an injected `Authorization: Bearer {{access_token}}` header (when absent).
If you already have per-user credentials or tokens, `login_sequence` can be omitted and each user can define request `headers` applied to every request for that user.
If the prompt declares `use these N users`, the scanner validates that the config contains exactly `N` users.
If the prompt includes `verify all requests from burp MCP history`, history requests must be provided.
Use only one OpenAPI source (`openapi_spec` or `openapi_spec_path`) and only one Burp history source (`burp_history_requests` or `burp_mcp_history_requests`).
OpenAPI path parameters like `/users/{id}` default to `1`; customize with `openapi_path_param_default`.
For better OpenAPI-derived test quality, you can also use:

- `openapi_path_param_defaults` (map parameter names to values),
- `openapi_operation_path_param_defaults` (map operationId -> parameter map),
- `openapi_expectation_overrides` (map operationId -> expected allowed users),
- `openapi_exclude_operation_ids` (skip specific operationIds such as `login`).

Minimal config example:

```json
{
  "burp_mcp_url": "http://localhost:8081/mcp/request",
  "ollama_url": "http://localhost:11434",
  "ollama_model": "llama3.1",
  "users": [
    {"name": "alice", "variables": {"username": "alice", "password": "alice-pass"}},
    {"name": "bob", "variables": {"username": "bob", "password": "bob-pass"}}
  ],
  "login_sequence": [
    {
      "request": {
        "method": "POST",
        "url": "https://target.example/api/login",
        "json": {"username": "{{username}}", "password": "{{password}}"}
      },
      "extract": {
        "access_token": {"from": "json", "path": "token"}
      }
    }
  ],
  "authorization_tests": [
    {
      "name": "read-account-1001",
      "request": {
        "method": "GET",
        "url": "https://target.example/api/accounts/1001",
        "headers": {"Authorization": "Bearer {{access_token}}"}
      },
      "expectations": {
        "allowed_users": ["alice"]
      }
    }
  ]
}
```

### Expectation mismatch classification

When `expectations.allowed_users` is provided:

- unauthorized successes are reported as `high` risk (`possible_idor_or_broken_access_control`),
- expected-allowed users receiving `401/403` are reported as `high` risk,
- expected-allowed users receiving `404/410` are reported as `medium` risk (`possible_stateful_test_or_missing_fixture`) to reduce false positives caused by stateful test data,
- other expected-allowed failures are reported as `medium` risk.

Instruction-based config example:

```json
{
  "instruction_prompt": "Hi, go to login.example.com and use username/password to obtain token for app.example.com, use these 3 users to test given in burp history requests",
  "users": [
    {"name": "alice", "variables": {"username": "alice", "password": "alice-pass"}},
    {"name": "bob", "variables": {"username": "bob", "password": "bob-pass"}},
    {"name": "carol", "variables": {"username": "carol", "password": "carol-pass"}}
  ],
  "burp_history_requests": [
    {"method": "GET", "url": "https://app.example.com/api/profile/100"},
    {"method": "GET", "url": "https://app.example.com/api/profile/101"}
  ]
}
```

OpenAPI-based config example:

```json
{
  "instruction_prompt": "go to login.example.com and obtain token for app.example.com use these 2 users",
  "users": [
    {"name": "alice", "variables": {"username": "alice", "password": "alice-pass"}},
    {"name": "bob", "variables": {"username": "bob", "password": "bob-pass"}}
  ],
  "openapi_spec_path": "/absolute/path/to/openapi.json"
}
```

Per-user header example without login sequence:

```json
{
  "users": [
    {"name": "john", "headers": {"Authorization": "Bearer X"}},
    {"name": "bob", "headers": {"Authorization": "Bearer Y"}}
  ],
  "authorization_tests": [
    {
      "name": "read-account-1001",
      "request": {
        "method": "GET",
        "url": "https://target.example/api/accounts/1001"
      }
    }
  ]
}
```

A ready-to-run token-only demo config is also included at `example/flask_idor_demo_config_tokens_only.json`.

## Local Flask example target

A runnable demo target is available in `example/`.

- `example/flask_idor_demo.py` starts a Flask server with 3 users (`admin`, `editor`, `viewer`), 13 example endpoints, and 3 intentional broken-access flaws.
- `example/flask_idor_demo_config.json` is a ready-to-run scanner configuration for that demo server.
- `example/flask_idor_demo_config_ollama.json` adds an Ollama-backed summary using `https://ollama.kscsc.local`.
- `example/flask_idor_demo_config_tokens_only.json` shows a no-login configuration that uses only per-user bearer tokens for the local demo app.
- `example/flask_idor_demo_config_openapi.json` demonstrates deriving tests from `example/flask_idor_demo_openapi.json`.
- `example/flask_idor_demo_config_burp_history.json` demonstrates deriving tests from Burp-history-style requests.
- `example/flask_idor_demo_config_burp_mcp.json` demonstrates routing scanner traffic through Burp MCP SSE (`http://127.0.0.1:9876/`).
- `example/flask_idor_demo_config_burp_mcp_openapi.json` demonstrates OpenAPI-derived tests executed through Burp MCP SSE.
- `example/README.md` explains how to run the sample locally.

The demo app also exposes `GET /` as a crawl-friendly landing page and `GET /openapi.json` for local OpenAPI testing.

If Ollama summarization fails, the report now includes `llm_summary_error` with a short error message.
When using HTTPS with internal certificates, set `ollama_ca_bundle_path` to the CA chain file (PEM).
