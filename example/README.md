# Example Flask target

This folder contains a small Flask app that can be used as a local target for `idor_scanner.py`.

Useful browser entry points:

- `GET /` landing page with links to all demo routes (useful for Burp crawl)
- `GET /openapi.json` OpenAPI 3.0 document for scanner OpenAPI-based generation

## Demo users

- `admin_user` / `admin-pass`
- `editor_user` / `editor-pass`
- `viewer_user` / `viewer-pass`

Roles are intentionally uneven:

- `admin` can use all 13 example endpoints
- `editor` can use a smaller subset
- `viewer` can use only a few `GET` endpoints

Three endpoints are intentionally vulnerable to broken access control / IDOR so the scanner has something to flag:

- `GET /api/reports/<report_id>`
- `GET /api/documents/<document_id>`
- `GET /api/admin/audit-events/<event_id>`

## Run it

Install Flask, then start the demo server:

```bash
python -m pip install flask
python example/flask_idor_demo.py
```

The example configs are YAML, so install PyYAML first (`pip install pyyaml`). The scanner also accepts JSON configs with no extra dependency.

In a second terminal, run the scanner with one of the included configs:

```bash
python idor_scanner.py --config example/ci_flask_demo_config.yaml
```

The expected result is that the scanner reports the intentional broken-access examples while the other routes follow the declared role expectations.

## Included config variants

- `example/ci_flask_demo_config.yaml` uses an explicit `login_sequence` to extract tokens from `/auth/login`, then runs expectation-based authorization tests.
- `example/ci_flask_demo_openapi_config.yaml` derives authorization tests from `example/flask_idor_demo_openapi.json` and tunes them with operation-specific path-param defaults (`openapi_operation_path_param_defaults`), expectation overrides (`openapi_expectation_overrides`), and operation filtering (`openapi_exclude_operation_ids`).

Both configs are the ones exercised by the DAST job in CI, so they are kept working against the demo target.

Run any variant with:

```bash
python idor_scanner.py --config /absolute/path/to/example/<config-file>.yaml
```

Two additional demo targets live in their own folders, each with matching configs and an OpenAPI spec:

- `example/oidc-http/` — an OIDC-style login flow (includes a YAML config variant).
- `example/post-http/` — a form/JSON POST login flow.

For internal TLS certificates, set `ollama_ca_bundle_path` in config so Python can validate an HTTPS Ollama endpoint.

Burp MCP note:

- This scanner supports MCP SSE transport on Burp root URL (for example `http://127.0.0.1:9876/`).
- It calls Burp tool `send_http1_request` under the hood, so requests are visible in Burp while scanning.
