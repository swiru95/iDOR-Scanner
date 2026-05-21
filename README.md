# iDOR-Scanner
Repository that assumes to help with iDORs supported by AI.

## Autonomous scanner

This repository now includes an autonomous CLI scanner:

- consumes a JSON configuration that describes a login/authentication sequence,
- authenticates **N users** and extracts tokens from responses,
- executes authorization test requests (direct HTTP or via `burp_mcp_url`),
- compares response status/body patterns and reports potential iDOR findings,
- can optionally request a final summary from an Ollama model (`ollama_url` + `ollama_model`).

Run:

```bash
python /home/runner/work/iDOR-Scanner/iDOR-Scanner/idor_scanner.py --config /absolute/path/to/config.json
```

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
