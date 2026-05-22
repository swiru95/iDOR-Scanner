# Example Flask target

This folder contains a small Flask app that can be used as a local target for `idor_scanner.py`.

## Demo users

- `admin_user` / `admin-pass`
- `editor_user` / `editor-pass`
- `viewer_user` / `viewer-pass`

Roles are intentionally uneven:

- `admin` can use all 10 example endpoints
- `editor` can use a smaller subset
- `viewer` can use only a few `GET` endpoints

Two endpoints are intentionally vulnerable to IDOR so the scanner has something to flag:

- `GET /api/reports/<report_id>`
- `GET /api/documents/<document_id>`

## Run it

Install Flask, then start the demo server:

```bash
python -m pip install flask
python example/flask_idor_demo.py
```

In a second terminal, run the scanner with the included config:

```bash
python idor_scanner.py --config example/flask_idor_demo_config.json
```

The expected result is that the scanner reports the two intentional IDOR examples while the other routes follow the declared role expectations.

## Included config variants

- `example/flask_idor_demo_config.json` uses the login flow and extracts tokens from `/auth/login`.
- `example/flask_idor_demo_config_ollama.json` is the same demo config but also asks for an LLM summary from `http://ollama.kscsc.local` using `llama3.1`.
- `example/flask_idor_demo_config_tokens_only.json` skips `login_sequence` entirely and uses per-user bearer tokens in `users[].headers`.

Run any variant with:

```bash
python idor_scanner.py --config /absolute/path/to/example/<config-file>.json
```

The token-only config uses demo tokens derived from the Flask app's intentionally unsigned local token format, so it is suitable only for this sample target.
