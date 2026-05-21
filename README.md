# iDOR-Scanner
Repository that aims to help with iDOR detection supported by AI.

## Autonomous scanner

This repository now includes an autonomous CLI scanner:

- consumes a JSON configuration that describes a login/authentication sequence,
- can derive the initial login sequence from a natural-language instruction prompt,
- authenticates **N users** and extracts tokens from responses,
- executes authorization test requests (direct HTTP or via `burp_mcp_url`),
- compares response status/body patterns and reports potential iDOR findings,
- can optionally request a final summary from an Ollama model (`ollama_url` + `ollama_model`).

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
If the prompt declares `use these N users`, the scanner validates that the config contains exactly `N` users.
If the prompt includes `verify all requests from burp MCP history`, history requests must be provided.
Use only one OpenAPI source (`openapi_spec` or `openapi_spec_path`) and only one Burp history source (`burp_history_requests` or `burp_mcp_history_requests`).
OpenAPI path parameters like `/users/{id}` default to `1`; customize with `openapi_path_param_default`.

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
