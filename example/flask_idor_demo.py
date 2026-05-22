from __future__ import annotations

import base64
import json
import uuid
import warnings
from pathlib import Path

from flask import Flask, Response, jsonify, request

app = Flask(__name__)
DEMO_WARNING = (
    "Demo-only Flask target: credentials are hardcoded for scanner testing and tokens are intentionally unsigned. "
    "Do not use this code in production."
)

USERS = {
    "admin_user": {
        "password": "admin-pass",
        "role": "admin",
        "display_name": "Alice Admin",
    },
    "editor_user": {
        "password": "editor-pass",
        "role": "editor",
        "display_name": "Eddie Editor",
    },
    "viewer_user": {
        "password": "viewer-pass",
        "role": "viewer",
        "display_name": "Vera Viewer",
    },
}

PROJECTS = {
    "project-alpha": {"name": "Alpha", "status": "active", "owner": "admin_user"},
    "project-beta": {"name": "Beta", "status": "review", "owner": "editor_user"},
}

REPORTS = {
    "report-admin-finance": {
        "owner": "admin_user",
        "classification": "restricted",
        "content": "Admin-only finance data",
    }
}

DOCUMENTS = {
    "doc-admin-secret": {
        "owner": "admin_user",
        "classification": "confidential",
        "content": "Admin-only document",
    }
}

INVOICES = {
    "invoice-admin-001": {
        "owner": "admin_user",
        "amount": 12000,
        "currency": "USD",
        "status": "paid",
    },
    "invoice-editor-001": {
        "owner": "editor_user",
        "amount": 4200,
        "currency": "USD",
        "status": "pending",
    },
    "invoice-viewer-001": {
        "owner": "viewer_user",
        "amount": 120,
        "currency": "USD",
        "status": "paid",
    },
}

TEAM_MEMBERS = {
    "team-core": ["admin_user", "editor_user"],
    "team-viewers": ["viewer_user"],
}

AUDIT_EVENTS = {
    "audit-security-001": {
        "classification": "admin-only",
        "message": "Root role granted to temporary user.",
    }
}

COMMENTS = []

ALL_PERMISSIONS = {
    "get_profile",
    "get_project",
    "get_project_summary",
    "get_report",
    "get_document",
    "create_project",
    "create_comment",
    "update_project",
    "patch_project_status",
    "delete_project",
    "get_invoice",
    "get_team_members",
}

ROLE_PERMISSIONS = {
    "admin": ALL_PERMISSIONS,
    "editor": {
        "get_profile",
        "get_project",
        "get_project_summary",
        "get_team_members",
        "create_project",
        "create_comment",
        "update_project",
        "patch_project_status",
    },
    "viewer": {
        "get_profile",
        "get_project",
        "get_project_summary",
        "get_team_members",
    },
}


def _encode_token(username: str) -> str:
    # Demo-only token format: readable and intentionally unsigned so the scanner can use a tiny local example app.
    # It has no signature verification and no expiration handling, so it must never be used in production.
    payload = {
        "sub": username,
        "role": USERS[username]["role"],
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _decode_token(token: str) -> dict | None:
    try:
        padded = token + "=" * (-len(token) % 4)
        payload = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
        data = json.loads(payload)
    except (ValueError, json.JSONDecodeError):
        return None

    username = data.get("sub")
    role = data.get("role")
    if username not in USERS or USERS[username]["role"] != role:
        return None
    return {"username": username, **USERS[username]}


def _error(status: int, error: str, message: str):
    return jsonify({"allowed": False, "error": error, "message": message}), status


def _require_authenticated_user():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, _error(401, "authentication_required", "Provide a Bearer token.")

    user = _decode_token(auth_header.split(" ", 1)[1].strip())
    if not user:
        return None, _error(401, "invalid_token", "Token is missing or invalid.")
    return user, None


def _require_permission(permission: str):
    user, error = _require_authenticated_user()
    if error:
        return None, error
    if permission not in ROLE_PERMISSIONS.get(user["role"], set()):
        return None, _error(403, "forbidden", f"Role '{user['role']}' is not allowed to access '{permission}'.")
    return user, None


@app.get("/")
def index():
    links = [
        ("OpenAPI spec", "/openapi.json"),
        ("Login (POST endpoint)", "/auth/login"),
        ("Profile", "/api/me/profile"),
        ("Project (alpha)", "/api/projects/project-alpha"),
        ("Project Summary (alpha)", "/api/projects/project-alpha/summary"),
        ("Report (intentional IDOR)", "/api/reports/report-admin-finance"),
        ("Document (intentional IDOR)", "/api/documents/doc-admin-secret"),
        ("Invoice (admin)", "/api/invoices/invoice-admin-001"),
        ("Team Members (core)", "/api/teams/team-core/members"),
        ("Audit Event (intentional broken access)", "/api/admin/audit-events/audit-security-001"),
        ("Create Project (POST endpoint)", "/api/projects"),
        ("Create Comment (POST endpoint)", "/api/projects/project-alpha/comments"),
        ("Update Project (PUT endpoint)", "/api/projects/project-alpha"),
        ("Patch Project Status (PATCH endpoint)", "/api/projects/project-alpha/status"),
        ("Delete Project (DELETE endpoint)", "/api/projects/project-beta"),
    ]
    items = "\n".join([f'<li><a href="{href}">{label}</a></li>' for label, href in links])
    html = (
        "<!doctype html><html><head><meta charset='utf-8'><title>iDOR Demo Index</title></head>"
        "<body><h1>iDOR Demo Target</h1>"
        "<p>Use this page as a crawl starting point in Burp. Most endpoints require Authorization and may return 401 without a Bearer token.</p>"
        "<ul>"
        f"{items}"
        "</ul>"
        "</body></html>"
    )
    return Response(html, mimetype="text/html")


@app.get("/openapi.json")
def openapi_spec():
    spec_path = Path(__file__).with_name("flask_idor_demo_openapi.json")
    try:
        content = spec_path.read_text(encoding="utf-8")
    except OSError:
        return _error(500, "openapi_unavailable", "OpenAPI spec file is missing from example folder.")
    return Response(content, mimetype="application/json")


@app.post("/auth/login")
def login():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "")
    password = payload.get("password", "")
    user = USERS.get(username)
    if not user or user["password"] != password:
        return _error(401, "invalid_credentials", "Username or password is invalid.")

    return jsonify(
        {
            "allowed": True,
            "token": _encode_token(username),
            "role": user["role"],
            "username": username,
        }
    )


@app.get("/api/me/profile")
def get_profile():
    user, error = _require_permission("get_profile")
    if error:
        return error
    return jsonify(
        {
            "allowed": True,
            "profile": {
                "username": user["username"],
                "role": user["role"],
                "display_name": user["display_name"],
            },
        }
    )


@app.get("/api/projects/<project_id>")
def get_project(project_id: str):
    user, error = _require_permission("get_project")
    if error:
        return error
    project = PROJECTS.get(project_id)
    if not project:
        return _error(404, "not_found", f"Project '{project_id}' was not found.")
    return jsonify({"allowed": True, "requested_by": user["username"], "project": project})


@app.get("/api/projects/<project_id>/summary")
def get_project_summary(project_id: str):
    user, error = _require_permission("get_project_summary")
    if error:
        return error
    project = PROJECTS.get(project_id)
    if not project:
        return _error(404, "not_found", f"Project '{project_id}' was not found.")
    return jsonify(
        {
            "allowed": True,
            "requested_by": user["username"],
            "summary": {
                "project_id": project_id,
                "name": project["name"],
                "status": project["status"],
            },
        }
    )


@app.get("/api/reports/<report_id>")
def get_report(report_id: str):
    # Intentional IDOR example: any authenticated user can read the report because object-level authorization is skipped.
    user, error = _require_authenticated_user()
    if error:
        return error
    report = REPORTS.get(report_id)
    if not report:
        return _error(404, "not_found", f"Report '{report_id}' was not found.")
    return jsonify(
        {
            "allowed": True,
            "warning": "intentional_idor_example",
            "requested_by": user["username"],
            "report": report,
        }
    )


@app.get("/api/documents/<document_id>")
def get_document(document_id: str):
    # Intentional IDOR example: any authenticated user can read the document because object-level authorization is skipped.
    user, error = _require_authenticated_user()
    if error:
        return error
    document = DOCUMENTS.get(document_id)
    if not document:
        return _error(404, "not_found", f"Document '{document_id}' was not found.")
    return jsonify(
        {
            "allowed": True,
            "warning": "intentional_idor_example",
            "requested_by": user["username"],
            "document": document,
        }
    )


@app.get("/api/invoices/<invoice_id>")
def get_invoice(invoice_id: str):
    user, error = _require_permission("get_invoice")
    if error:
        return error
    invoice = INVOICES.get(invoice_id)
    if not invoice:
        return _error(404, "not_found", f"Invoice '{invoice_id}' was not found.")
    if user["role"] != "admin" and invoice["owner"] != user["username"]:
        return _error(403, "forbidden", "You can access only your own invoices.")
    return jsonify({"allowed": True, "requested_by": user["username"], "invoice": invoice})


@app.get("/api/teams/<team_id>/members")
def get_team_members(team_id: str):
    user, error = _require_permission("get_team_members")
    if error:
        return error
    members = TEAM_MEMBERS.get(team_id)
    if not members:
        return _error(404, "not_found", f"Team '{team_id}' was not found.")
    return jsonify({"allowed": True, "requested_by": user["username"], "team_id": team_id, "members": members})


@app.get("/api/admin/audit-events/<event_id>")
def get_audit_event(event_id: str):
    # Intentional broken access control: any authenticated user can read admin-only audit events.
    user, error = _require_authenticated_user()
    if error:
        return error
    event = AUDIT_EVENTS.get(event_id)
    if not event:
        return _error(404, "not_found", f"Audit event '{event_id}' was not found.")
    return jsonify(
        {
            "allowed": True,
            "warning": "intentional_broken_access_control_example",
            "requested_by": user["username"],
            "event": event,
        }
    )


@app.post("/api/projects")
def create_project():
    user, error = _require_permission("create_project")
    if error:
        return error
    payload = request.get_json(silent=True) or {}
    project_id = payload.get("project_id") or f"project-{uuid.uuid4().hex[:8]}"
    if project_id in PROJECTS:
        return _error(409, "conflict", f"Project '{project_id}' already exists.")
    PROJECTS[project_id] = {
        "name": payload.get("name", "Unnamed"),
        "status": payload.get("status", "draft"),
        "owner": user["username"],
    }
    return jsonify({"allowed": True, "created_by": user["username"], "project_id": project_id}), 201


@app.post("/api/projects/<project_id>/comments")
def create_comment(project_id: str):
    user, error = _require_permission("create_comment")
    if error:
        return error
    if project_id not in PROJECTS:
        return _error(404, "not_found", f"Project '{project_id}' was not found.")
    payload = request.get_json(silent=True) or {}
    COMMENTS.append(
        {
            "project_id": project_id,
            "author": user["username"],
            "message": payload.get("message", ""),
        }
    )
    return jsonify({"allowed": True, "commented_by": user["username"], "project_id": project_id}), 201


@app.put("/api/projects/<project_id>")
def update_project(project_id: str):
    user, error = _require_permission("update_project")
    if error:
        return error
    project = PROJECTS.get(project_id)
    if not project:
        return _error(404, "not_found", f"Project '{project_id}' was not found.")
    payload = request.get_json(silent=True) or {}
    project.update(
        {
            "name": payload.get("name", project["name"]),
            "status": payload.get("status", project["status"]),
        }
    )
    return jsonify({"allowed": True, "updated_by": user["username"], "project": project})


@app.patch("/api/projects/<project_id>/status")
def patch_project_status(project_id: str):
    user, error = _require_permission("patch_project_status")
    if error:
        return error
    project = PROJECTS.get(project_id)
    if not project:
        return _error(404, "not_found", f"Project '{project_id}' was not found.")
    payload = request.get_json(silent=True) or {}
    project["status"] = payload.get("status", project["status"])
    return jsonify({"allowed": True, "updated_by": user["username"], "project": project})


@app.delete("/api/projects/<project_id>")
def delete_project(project_id: str):
    user, error = _require_permission("delete_project")
    if error:
        return error
    project = PROJECTS.pop(project_id, None)
    if not project:
        return _error(404, "not_found", f"Project '{project_id}' was not found.")
    return jsonify({"allowed": True, "deleted_by": user["username"], "project_id": project_id})


if __name__ == "__main__":
    warnings.warn(DEMO_WARNING, stacklevel=1)
    app.run(host="127.0.0.1", port=5000, debug=False)
