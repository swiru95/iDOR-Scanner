from __future__ import annotations

import base64
import json
import uuid
import warnings

from flask import Flask, jsonify, request

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
}

ROLE_PERMISSIONS = {
    "admin": ALL_PERMISSIONS,
    "editor": {
        "get_profile",
        "get_project",
        "get_project_summary",
        "create_project",
        "create_comment",
        "update_project",
        "patch_project_status",
    },
    "viewer": {
        "get_profile",
        "get_project",
        "get_project_summary",
    },
}


def _encode_token(username: str) -> str:
    # Demo-only token format: readable and intentionally unsigned so the scanner can use a tiny local example app.
    # Never use this token format in production.
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


@app.post("/api/projects")
def create_project():
    user, error = _require_permission("create_project")
    if error:
        return error
    payload = request.get_json(silent=True) or {}
    project_id = payload.get("project_id") or f"project-{uuid.uuid4().hex[:8]}"
    PROJECTS[project_id] = {
        "name": payload.get("name", "Unnamed"),
        "status": payload.get("status", "draft"),
        "owner": payload.get("owner", user["username"]),
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
            "owner": payload.get("owner", project["owner"]),
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
