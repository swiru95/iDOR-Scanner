#!/usr/bin/env python3
import argparse
import base64
import concurrent.futures
import copy
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

TEMPLATE_PATTERN = r"\{\{\s*([a-zA-Z0-9_\.\-]+)\s*\}\}"
OPENAPI_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
UNAUTHENTICATED_USER = "unauthenticated"


def _build_ssl_context(verify: bool, ca_bundle_path: str) -> Optional[ssl.SSLContext]:
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca_bundle_path:
        return ssl.create_default_context(cafile=ca_bundle_path)
    return None


@dataclass
class HTTPResult:
    status: int
    headers: Dict[str, str]
    body: str

    @property
    def body_hash(self) -> str:
        return hashlib.sha256(self.body.encode("utf-8")).hexdigest()[:16]


class RequestExecutor:
    def send(self, request_spec: Dict[str, Any]) -> HTTPResult:
        raise NotImplementedError


class DirectHTTPExecutor(RequestExecutor):
    def __init__(self, timeout_seconds: float = 20.0, ssl_verify: bool = True, ca_bundle_path: str = ""):
        self.timeout_seconds = timeout_seconds
        self._ssl_context = _build_ssl_context(ssl_verify, ca_bundle_path)

    def send(self, request_spec: Dict[str, Any]) -> HTTPResult:
        method = request_spec.get("method", "GET").upper()
        url = request_spec["url"]
        headers = {k: str(v) for k, v in request_spec.get("headers", {}).items()}
        body_data = _encode_body(request_spec, headers)
        req = urllib.request.Request(url=url, data=body_data, headers=headers, method=method)
        # Custom opener to prevent automatic redirect following
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(NoRedirect)
        try:
            with opener.open(req, timeout=self.timeout_seconds) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return HTTPResult(status=resp.status, headers=dict(resp.headers.items()), body=body)
        except urllib.error.HTTPError as e:
            # For 3xx, still return headers (e.g., Location)
            body = e.read().decode("utf-8", errors="replace")
            return HTTPResult(status=e.code, headers=dict(e.headers.items()), body=body)


class BurpMCPExecutor(RequestExecutor):
    def __init__(self, burp_mcp_url: str, timeout_seconds: float = 20.0):
        self.burp_mcp_url = burp_mcp_url
        self.timeout_seconds = timeout_seconds
        self._mode: Optional[str] = None

    def _detect_mode(self) -> str:
        if self._mode:
            return self._mode
        try:
            req = urllib.request.Request(self.burp_mcp_url, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                content_type = str(resp.headers.get("Content-Type", "")).lower()
                if "text/event-stream" in content_type:
                    self._mode = "mcp_sse"
                else:
                    self._mode = "legacy_http"
        except Exception:
            self._mode = "legacy_http"
        return self._mode

    def _post_json(self, url: str, payload_obj: Dict[str, Any]) -> None:
        payload = json.dumps(payload_obj).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout_seconds):
            return

    def _extract_sse_post_url(self, sse_resp: Any) -> str:
        # MCP SSE transport sends an "endpoint" event with relative URL containing sessionId.
        for _ in range(40):
            raw = sse_resp.readline()
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").strip()
            if line.startswith("data:"):
                endpoint = line.split("data:", 1)[1].strip()
                if endpoint:
                    return urljoin(self.burp_mcp_url, endpoint)
        return self.burp_mcp_url

    def _build_http1_content(self, request_spec: Dict[str, Any]) -> Dict[str, Any]:
        method = request_spec.get("method", "GET").upper()
        parsed = urlparse(request_spec["url"])
        target_hostname = parsed.hostname or ""
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        uses_https = parsed.scheme == "https"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        headers = {k: str(v) for k, v in request_spec.get("headers", {}).items()}
        headers.setdefault("Host", parsed.netloc or target_hostname)
        headers.setdefault("Connection", "close")

        body_data = _encode_body(request_spec, headers)
        if body_data is not None:
            headers["Content-Length"] = str(len(body_data))

        start_line = f"{method} {path} HTTP/1.1"
        header_lines = [f"{k}: {v}" for k, v in headers.items()]
        raw = "\r\n".join([start_line, *header_lines, "", ""])
        if body_data is not None:
            raw += body_data.decode("utf-8", errors="replace")

        return {
            "targetHostname": target_hostname,
            "targetPort": target_port,
            "usesHttps": uses_https,
            "content": raw,
        }

    def _parse_http_response_from_text(self, tool_text: str) -> HTTPResult:
        marker = "httpResponse="
        start = tool_text.find(marker)
        if start < 0:
            return HTTPResult(status=0, headers={}, body=tool_text)
        response_blob = tool_text[start + len(marker) :]
        tail = ", messageAnnotations="
        end = response_blob.find(tail)
        if end >= 0:
            response_blob = response_blob[:end]

        header_blob, sep, body = response_blob.partition("\r\n\r\n")
        if not sep:
            return HTTPResult(status=0, headers={}, body=response_blob)
        header_lines = header_blob.split("\r\n")
        status_line = header_lines[0] if header_lines else ""
        parts = status_line.split(" ")
        status = 0
        if len(parts) > 1 and parts[1].isdigit():
            status = int(parts[1])

        headers: Dict[str, str] = {}
        for line in header_lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        return HTTPResult(status=status, headers=headers, body=body)

    def _send_via_mcp_sse(self, request_spec: Dict[str, Any]) -> HTTPResult:
        sse_req = urllib.request.Request(self.burp_mcp_url, method="GET")
        with urllib.request.urlopen(sse_req, timeout=self.timeout_seconds) as sse_resp:
            post_url = self._extract_sse_post_url(sse_resp)

            self._post_json(
                post_url,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "idor-scanner", "version": "1.0"},
                    },
                },
            )
            self._post_json(
                post_url,
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {},
                },
            )

            call_id = 2
            self._post_json(
                post_url,
                {
                    "jsonrpc": "2.0",
                    "id": call_id,
                    "method": "tools/call",
                    "params": {
                        "name": "send_http1_request",
                        "arguments": self._build_http1_content(request_spec),
                    },
                },
            )

            deadline = time.time() + self.timeout_seconds
            while time.time() < deadline:
                raw = sse_resp.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                payload = line.split("data:", 1)[1].strip()
                try:
                    msg = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                if msg.get("id") != call_id:
                    continue
                result = msg.get("result", {})
                if result.get("isError"):
                    text_items = result.get("content", [])
                    text = ""
                    if text_items and isinstance(text_items[0], dict):
                        text = str(text_items[0].get("text", ""))
                    return HTTPResult(status=0, headers={}, body=text or "Burp MCP tools/call returned an error")

                text = ""
                for item in result.get("content", []):
                    if isinstance(item, dict) and "text" in item:
                        text = str(item.get("text", ""))
                        break
                return self._parse_http_response_from_text(text)

        return HTTPResult(status=0, headers={}, body="Timed out waiting for Burp MCP response over SSE")

    def _send_via_legacy_http(self, request_spec: Dict[str, Any]) -> HTTPResult:
        payload = json.dumps({"request": request_spec}).encode("utf-8")
        req = urllib.request.Request(
            self.burp_mcp_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                response = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            response = json.loads(e.read().decode("utf-8"))

        body = response.get("body", "")
        if response.get("body_base64"):
            body = base64.b64decode(response["body_base64"]).decode("utf-8", errors="replace")
        return HTTPResult(
            status=int(response.get("status", 0)),
            headers={k: str(v) for k, v in response.get("headers", {}).items()},
            body=str(body),
        )

    def send(self, request_spec: Dict[str, Any]) -> HTTPResult:
        mode = self._detect_mode()
        if mode == "mcp_sse":
            return self._send_via_mcp_sse(request_spec)
        return self._send_via_legacy_http(request_spec)


def _encode_body(request_spec: Dict[str, Any], headers: Dict[str, str]) -> Optional[bytes]:
    if "json" in request_spec:
        headers.setdefault("Content-Type", "application/json")
        return json.dumps(request_spec["json"]).encode("utf-8")
    if "body" in request_spec:
        body = request_spec["body"]
        if isinstance(body, str):
            return body.encode("utf-8")
        if isinstance(body, (dict, list)):
            headers.setdefault("Content-Type", "application/json")
            return json.dumps(body).encode("utf-8")
    return None


def _lookup_context_value(context: Dict[str, Any], key: str) -> str:
    if key.startswith("env."):
        return os.environ.get(key[4:], "")
    if key in context:
        return "" if context[key] is None else str(context[key])
    if "." not in key:
        return ""
    nested = _read_json_path(context, key)
    return nested


def render_template(value: Any, context: Dict[str, Any]) -> Any:
    if isinstance(value, str):
        return re.sub(TEMPLATE_PATTERN, lambda m: _lookup_context_value(context, m.group(1)), value)
    if isinstance(value, dict):
        return {k: render_template(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [render_template(v, context) for v in value]
    return value


def _apply_user_headers(request_spec: Dict[str, Any], user: Dict[str, Any], context: Dict[str, Any]) -> None:
    user_headers = user.get("headers", {})
    if not isinstance(user_headers, dict) or not user_headers:
        return
    rendered_headers = render_template(copy.deepcopy(user_headers), context)
    request_headers = request_spec.setdefault("headers", {})
    for header_name, header_value in rendered_headers.items():
        request_headers[str(header_name)] = str(header_value)


def extract_value(result: HTTPResult, rule: Dict[str, str]) -> str:
    source = rule.get("from", "json")
    if source == "header":
        header_val = result.headers.get(rule["name"], "")
        pattern = rule.get("pattern")
        if pattern:
            match = re.search(pattern, header_val)
            return match.group(1) if match else ""
        return header_val
    if source == "set_cookie":
        cookie_name = rule.get("name", "")
        raw = result.headers.get("Set-Cookie", "")
        for part in raw.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip() == cookie_name:
                    return v.strip()
        return ""
    if source == "regex":
        match = re.search(rule["pattern"], result.body)
        return match.group(1) if match else ""
    try:
        json_payload = json.loads(result.body or "{}")
    except json.JSONDecodeError:
        return ""
    return _read_json_path(json_payload, rule.get("path", ""))


def _is_success(status: int) -> bool:
    return 200 <= status < 300


def _is_authz_denial(status: int) -> bool:
    return status in {401, 403}


def _is_not_found(status: int) -> bool:
    return status in {404, 410}


def _read_json_path(payload: Any, path: str) -> str:
    current = payload
    for part in [p for p in path.split(".") if p]:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return ""
    if isinstance(current, (dict, list)):
        return json.dumps(current)
    return "" if current is None else str(current)


def evaluate_test_results(test_name: str, user_results: Dict[str, HTTPResult], expectations: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    details = {
        user: {
            "status": result.status,
            "body_hash": result.body_hash,
            "body_preview": result.body[:500],
        }
        for user, result in user_results.items()
    }

    finding = "authorization_behavior_observed"
    risk = "low"

    if expectations:
        allowed = set(expectations.get("allowed_users", []))
        unauthorized_successes = []
        expected_denials = []
        expected_not_found = []
        expected_other_failures = []
        for user, result in user_results.items():
            if user in allowed:
                if _is_success(result.status):
                    continue
                if _is_authz_denial(result.status):
                    expected_denials.append(f"{user} should be allowed but got {result.status}")
                elif _is_not_found(result.status):
                    expected_not_found.append(f"{user} should be allowed but got {result.status}")
                else:
                    expected_other_failures.append(f"{user} should be allowed but got {result.status}")
            elif _is_success(result.status):
                unauthorized_successes.append(f"{user} should not be allowed but got {result.status}")

        notes = unauthorized_successes + expected_denials + expected_not_found + expected_other_failures
        if unauthorized_successes or expected_denials:
            finding = "possible_idor_or_broken_access_control"
            risk = "high"
        elif expected_not_found:
            finding = "possible_stateful_test_or_missing_fixture"
            risk = "medium"
            notes.append("Expected-allowed users received not found responses; verify test data setup and endpoint side effects.")
        elif expected_other_failures:
            finding = "unexpected_authorization_or_application_behavior"
            risk = "medium"
    else:
        # The anonymous probe must not pollute the cross-user comparison: its
        # 401 would otherwise make "all users succeeded" perpetually false. Judge
        # authenticated users among themselves, then assess the anon probe alone.
        anon_result = user_results.get(UNAUTHENTICATED_USER)
        real_results = {u: r for u, r in user_results.items() if u != UNAUTHENTICATED_USER}
        notes = []

        all_success = bool(real_results) and all(_is_success(r.status) for r in real_results.values())
        if all_success and len(real_results) > 1:
            hashes = {r.body_hash for r in real_results.values()}
            if len(hashes) == 1:
                finding = "possible_idor_identical_successful_access"
                risk = "medium"
                notes.append("All tested users received successful and identical responses.")
            else:
                finding = "possible_cross_user_data_leak"
                risk = "medium"
                notes.append("All users got successful responses but with different content; may indicate cross-user data access. Full bodies included for LLM analysis.")
                for user, result in real_results.items():
                    details[user]["full_body"] = result.body
        else:
            notes.append("Differences detected or non-success responses observed.")

        if anon_result is not None and _is_success(anon_result.status):
            notes.append(f"Unauthenticated request succeeded with {anon_result.status}; endpoint may be missing authentication.")
            finding = "possible_idor_or_broken_access_control"
            risk = "high"

    return {
        "test": test_name,
        "finding": finding,
        "risk": risk,
        "details": details,
        "notes": notes,
    }


def authenticate_users(config: Dict[str, Any], executor: RequestExecutor) -> Dict[str, Dict[str, Any]]:
    shared = config.get("shared_variables", {})
    sequence = config.get("login_sequence", [])
    max_workers = int(config.get("max_concurrent_requests", 5))

    def _login_user(user: Dict[str, Any]) -> tuple:
        user_name = user["name"]
        context = {**shared, **user.get("variables", {})}
        for step in sequence:
            request_spec = render_template(copy.deepcopy(step["request"]), context)
            _apply_user_headers(request_spec, user, context)
            result = executor.send(request_spec)
            for target, rule in step.get("extract", {}).items():
                context[target] = extract_value(result, rule)
        return user_name, context

    user_contexts: Dict[str, Dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for user_name, context in pool.map(_login_user, config.get("users", [])):
            user_contexts[user_name] = context
    return user_contexts


def run_authorization_tests(config: Dict[str, Any], user_contexts: Dict[str, Dict[str, Any]], executor: RequestExecutor) -> List[Dict[str, Any]]:
    findings = []
    users = config.get("users", [])
    shared = config.get("shared_variables", {})
    max_workers = int(config.get("max_concurrent_requests", 5))

    for test in config.get("authorization_tests", []):
        def _run_for_user(user: Dict[str, Any], _test: Dict[str, Any] = test) -> tuple:
            user_name = user["name"]
            context = {**user_contexts[user_name], **_test.get("variables", {})}
            request_spec = render_template(copy.deepcopy(_test["request"]), context)
            _apply_user_headers(request_spec, user, context)
            return user_name, executor.send(request_spec)

        per_user_results: Dict[str, HTTPResult] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            for user_name, result in pool.map(_run_for_user, users):
                per_user_results[user_name] = result

        # Add unauthenticated test: render against shared variables only (no
        # per-user token) and drop every credential-bearing header so the probe
        # is genuinely anonymous.
        anon_request = render_template(copy.deepcopy(test["request"]), dict(shared))
        anon_headers = anon_request.get("headers")
        if isinstance(anon_headers, dict):
            for header_name in [h for h in anon_headers if h.lower() in {"authorization", "cookie"}]:
                del anon_headers[header_name]
            if not anon_headers:
                del anon_request["headers"]
        anon_result = executor.send(anon_request)
        per_user_results[UNAUTHENTICATED_USER] = anon_result

        finding = evaluate_test_results(
            test_name=test.get("name", "unnamed_test"),
            user_results=per_user_results,
            expectations=test.get("expectations"),
        )
        finding["request_method"] = test["request"].get("method", "GET").upper()
        finding["request_url"] = test["request"].get("url", "")
        allowed = test.get("expectations", {}).get("allowed_users")
        if allowed is not None:
            finding["allowed_users"] = list(allowed)
        findings.append(finding)
    return findings


def maybe_generate_llm_summary(config: Dict[str, Any], report: Dict[str, Any]) -> Dict[str, str]:
    model = config.get("ollama_model")
    base_url = config.get("ollama_url")
    if not model or not base_url:
        return {}

    ssl_verify = bool(config.get("ollama_ssl_verify", True))
    ca_bundle_path = str(config.get("ollama_ca_bundle_path", "")).strip()
    ssl_context: Optional[ssl.SSLContext] = None
    if not ssl_verify:
        ssl_context = _build_ssl_context(False, "")
    elif ca_bundle_path:
        if not os.path.isfile(ca_bundle_path):
            return {"llm_summary_error": f"ollama_ca_bundle_path does not exist: {ca_bundle_path}"}
        try:
            ssl_context = ssl.create_default_context(cafile=ca_bundle_path)
        except Exception as exc:
            return {"llm_summary_error": f"Failed to load ollama_ca_bundle_path '{ca_bundle_path}': {exc}"}

    prompt = (
        "Summarize iDOR scan findings. Focus on authorization anomalies and likely false positives.\n\n"
        + json.dumps(report, indent=2)
    )
    payload = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
    req = urllib.request.Request(
        base_url.rstrip("/") + "/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ssl_context, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            summary = data.get("response")
            if summary:
                return {"llm_summary": str(summary)}
            return {"llm_summary_error": "Ollama responded without a 'response' field."}
    except Exception as exc:
        return {"llm_summary_error": str(exc)}


_FINDING_ANALYSIS_VERDICTS = frozenset({
    "confirmed_idor", "likely_idor", "possible_idor", "false_positive", "clean"
})


def _llm_analyze_single_finding(finding: Dict[str, Any], config: Dict[str, Any]) -> Optional[Dict[str, str]]:
    model = config.get("ollama_model")
    base_url = config.get("ollama_url")
    if not model or not base_url:
        return None

    ssl_verify = bool(config.get("ollama_ssl_verify", True))
    ca_bundle_path = str(config.get("ollama_ca_bundle_path", "")).strip()

    user_lines = []
    for user_name, detail in finding.get("details", {}).items():
        status = detail.get("status", "?")
        preview = detail.get("body_preview", "").strip().replace("\n", " ")[:300]
        user_lines.append(f"  {user_name}: HTTP {status} — {preview}")

    notes_block = "; ".join(finding.get("notes", [])) or "none"
    allowed_users = finding.get("allowed_users")
    allowed_block = (
        f"Expected to allow: {', '.join(allowed_users)}\n"
        if allowed_users is not None
        else ""
    )
    prompt = (
        "You are a security analyst reviewing an HTTP authorization test result.\n\n"
        f"Endpoint: {finding.get('request_method', 'GET')} {finding.get('request_url', '')}\n"
        f"{allowed_block}"
        f"Scanner verdict: {finding.get('finding', '')} (risk: {finding.get('risk', '')})\n"
        f"Scanner notes: {notes_block}\n\n"
        "Per-user HTTP responses:\n"
        + "\n".join(user_lines)
        + "\n\nDoes this show IDOR or broken access control? "
        "Consider: unauthorized 2xx access, sensitive data from other users in response bodies, "
        "partial leaks in error responses, suspicious patterns across users.\n\n"
        'Return JSON only: {"verdict": "confirmed_idor|likely_idor|possible_idor|false_positive|clean", '
        '"reasoning": "one concise sentence", "confidence": "high|medium|low"}'
    )

    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0},
    }).encode("utf-8")
    ctx = _build_ssl_context(ssl_verify, ca_bundle_path)
    api_url = base_url.rstrip("/") + "/api/generate"

    last_exc: Exception = RuntimeError("no attempts made")
    for attempt in range(1, 4):
        try:
            req = urllib.request.Request(api_url, data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
                response = json.loads(resp.read().decode("utf-8"))
            raw = response.get("response", "")
            sanitized = _sanitize_llm_json(raw)
            start = sanitized.find("{")
            end = sanitized.rfind("}")
            if start == -1 or end == -1:
                raise ValueError("No JSON object in LLM response")
            result = json.loads(sanitized[start : end + 1])
            verdict = result.get("verdict", "")
            if verdict not in _FINDING_ANALYSIS_VERDICTS:
                raise ValueError(f"Unexpected verdict value: {verdict!r}")
            return {
                "verdict": verdict,
                "reasoning": str(result.get("reasoning", "")),
                "confidence": str(result.get("confidence", "low")),
            }
        except Exception as exc:
            last_exc = exc

    return {"verdict": "error", "reasoning": str(last_exc), "confidence": "low"}


def llm_analyze_findings(findings: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not config.get("llm_analyze_responses"):
        return findings
    if not config.get("ollama_url") or not config.get("ollama_model"):
        return findings
    for finding in findings:
        analysis = _llm_analyze_single_finding(finding, config)
        if analysis:
            finding["llm_analysis"] = analysis
    return findings


def _ensure_url(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if not parsed.netloc:
        return ""
    scheme = parsed.scheme or "https"
    path = parsed.path or ""
    return f"{scheme}://{parsed.netloc}{path}"


def _extract_prompt_instruction(prompt: str) -> Dict[str, Any]:
    lowered = prompt.lower()
    login_match = re.search(r"go to\s+([a-zA-Z0-9\.\-/:_]+)", lowered)
    app_match = re.search(r"obtain token for\s+([a-zA-Z0-9\.\-/:_]+)", lowered)
    users_match = re.search(r"use these\s+(\d+)\s+users", lowered)
    verify_burp_history = bool(re.search(r"verify all requests.*burp(\s+mcp)? history", lowered))

    return {
        "login_target": _ensure_url(login_match.group(1)) if login_match else "",
        "app_target": _ensure_url(app_match.group(1)) if app_match else "",
        "users_count": int(users_match.group(1)) if users_match else None,
        "verify_burp_history": verify_burp_history,
    }


def _build_login_sequence_from_prompt(login_target: str, app_target: str) -> List[Dict[str, Any]]:
    if not login_target:
        return []
    parsed = urlparse(login_target)
    default_login_url = f"{parsed.scheme}://{parsed.netloc}/login"
    return [
        {
            "request": {
                "method": "POST",
                "url": default_login_url,
                "json": {
                    "username": "{{username}}",
                    "password": "{{password}}",
                    "audience": app_target,
                },
            },
            "extract": {
                "access_token": {"from": "json", "path": "token"},
            },
        }
    ]


_LOGIN_SEQUENCE_SCHEMA_EXAMPLE = """[
  {
    "request": {
      "method": "POST",
      "url": "https://auth.example.com/login",
      "json": {"username": "{{username}}", "password": "{{password}}"}
    },
    "extract": {
      "access_token": {"from": "json", "path": "data.token"},
      "refresh_token": {"from": "json", "path": "data.refresh"}
    }
  },
  {
    "request": {
      "method": "POST",
      "url": "https://app.example.com/api/token/exchange",
      "headers": {"Authorization": "Bearer {{access_token}}"},
      "json": {"audience": "app"}
    },
    "extract": {
      "app_token": {"from": "json", "path": "token"}
    }
  }
]"""


def _sanitize_llm_json(text: str) -> str:
    """Fix the most common ways LLMs break JSON validity."""
    # Strip markdown code fences
    text = re.sub(r"```[a-zA-Z]*\n?", "", text).strip()
    # Remove JS-style comments — only strip // that starts a line (after optional whitespace)
    # so that URLs containing http:// are never mistakenly treated as comments
    text = re.sub(r"^\s*//[^\n]*\n?", "", text, flags=re.MULTILINE)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    # Remove trailing commas before } or ]
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    # Quote unquoted {{...}} template vars (e.g. "key": {{var}} → "key": "{{var}}")
    text = re.sub(r"([:,\[]\s*)(\{\{[^}]+\}\})", r'\1"\2"', text)
    # Escape literal control characters inside JSON strings
    def _escape_ctrl_in_string(m: re.Match) -> str:
        inner = m.group(1).replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        return f'"{inner}"'
    text = re.sub(r'"([^"\\]*(?:\\.[^"\\]*)*)"', _escape_ctrl_in_string, text, flags=re.DOTALL)
    return text


def _extract_json_from_llm_output(text: str) -> Any:
    text = _sanitize_llm_json(text)
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON array found in LLM output")
    return json.loads(text[start : end + 1])


def _generate_login_sequence_with_ollama(
    prompt: str,
    user_variable_names: List[str],
    config: Dict[str, Any],
) -> Optional[List[Dict[str, Any]]]:
    model = config.get("ollama_model")
    base_url = config.get("ollama_url")
    if not model or not base_url:
        return None

    ssl_verify = bool(config.get("ollama_ssl_verify", True))
    ca_bundle_path = str(config.get("ollama_ca_bundle_path", "")).strip()

    variables_hint = (
        ", ".join(f"{{{{{v}}}}}" for v in user_variable_names)
        if user_variable_names
        else "{{username}}, {{password}}"
    )

    extract_hint = (
        '{"from": "json", "path": "a.b"}  or  {"from": "header", "name": "X-Token"}'
        '  or  {"from": "set_cookie", "name": "session"}'
    )
    llm_prompt = (
        f"Generate a login_sequence JSON array for this authentication flow:\n\n"
        f"{prompt}\n\n"
        f"Available per-user variables (use as {{{{variable}}}} placeholders in strings): {variables_hint}\n"
        f"Extraction rule formats: {extract_hint}\n\n"
        f"Example output:\n{_LOGIN_SEQUENCE_SCHEMA_EXAMPLE}\n\n"
        f"Return ONLY the JSON array, nothing else:"
    )

    payload = json.dumps({
        "model": model,
        "prompt": llm_prompt,
        "stream": False,
        "options": {"temperature": 0},
    }).encode("utf-8")
    ctx = _build_ssl_context(ssl_verify, ca_bundle_path)
    api_url = base_url.rstrip("/") + "/api/generate"

    last_exc: Exception = RuntimeError("no attempts made")
    for attempt in range(1, 4):
        req = urllib.request.Request(api_url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
                response = json.loads(resp.read().decode("utf-8"))
            raw = response.get("response", "")
            sequence = _extract_json_from_llm_output(raw)
            if not isinstance(sequence, list) or not sequence:
                raise ValueError("LLM returned empty or non-list result")
            if not all(isinstance(step, dict) and "request" in step for step in sequence):
                raise ValueError("One or more steps missing required 'request' key")
            return sequence
        except Exception as exc:
            last_exc = exc
            if attempt < 3:
                print(f"[iDOR] Ollama login sequence attempt {attempt} failed ({exc}), retrying…", file=sys.stderr)

    print(f"[iDOR] Warning: Ollama login sequence generation failed ({last_exc}), falling back to defaults", file=sys.stderr)
    return None


def _build_authorization_tests_from_burp_history(history_requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    tests: List[Dict[str, Any]] = []
    for index, request_spec in enumerate(history_requests, start=1):
        request_copy = copy.deepcopy(request_spec)
        headers = request_copy.setdefault("headers", {})
        if "Authorization" not in headers:
            headers["Authorization"] = "Bearer {{access_token}}"
        tests.append(
            {
                "name": f"burp-history-{index}",
                "request": request_copy,
            }
        )
    return tests


def _load_openapi_spec(config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    inline_spec = config.get("openapi_spec")
    spec_path = config.get("openapi_spec_path")
    if inline_spec is not None and spec_path:
        raise ValueError("Provide only one of openapi_spec or openapi_spec_path, not both")
    if isinstance(inline_spec, dict):
        return inline_spec

    if not spec_path:
        return None
    try:
        with open(spec_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError as exc:
        raise ValueError(f"openapi_spec_path does not exist: {spec_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"openapi_spec_path must point to valid JSON: {spec_path}") from exc


def _normalize_openapi_request_url(
    base_url: str,
    path: str,
    path_param_default: str,
    path_param_defaults: Optional[Dict[str, str]] = None,
) -> str:
    replacement = path_param_default or "1"
    named_defaults = path_param_defaults or {}

    def _resolve_param(match: re.Match[str]) -> str:
        param_name = match.group(1)
        return str(named_defaults.get(param_name, replacement))

    normalized_path = re.sub(r"\{([^}]+)\}", _resolve_param, path)
    root = (base_url or "").rstrip("/")
    if not root:
        return normalized_path
    return f"{root}{normalized_path}"


def _build_authorization_tests_from_openapi(
    spec: Dict[str, Any],
    path_param_default: str = "1",
    path_param_defaults: Optional[Dict[str, str]] = None,
    operation_path_param_defaults: Optional[Dict[str, Dict[str, str]]] = None,
    exclude_operation_ids: Optional[List[str]] = None,
    expectation_overrides: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    base_url = ""
    servers = spec.get("servers", [])
    if isinstance(servers, list) and servers:
        first_server = servers[0]
        if isinstance(first_server, dict):
            base_url = str(first_server.get("url", "")).strip()

    operation_defaults = operation_path_param_defaults or {}
    global_param_defaults = path_param_defaults or {}
    excluded = set(exclude_operation_ids or [])
    expectation_map = expectation_overrides or {}

    tests: List[Dict[str, Any]] = []
    for path, methods in spec.get("paths", {}).items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if str(method).lower() not in OPENAPI_METHODS:
                continue
            operation_id = ""
            if isinstance(operation, dict):
                operation_id = str(operation.get("operationId", "")).strip()
            if operation_id and operation_id in excluded:
                continue

            merged_param_defaults = dict(global_param_defaults)
            op_param_defaults = operation_defaults.get(operation_id, {})
            if isinstance(op_param_defaults, dict):
                merged_param_defaults.update({k: str(v) for k, v in op_param_defaults.items()})

            request_spec: Dict[str, Any] = {
                "method": str(method).upper(),
                "url": _normalize_openapi_request_url(
                    base_url,
                    str(path),
                    path_param_default,
                    path_param_defaults=merged_param_defaults,
                ),
                "headers": {"Authorization": "Bearer {{access_token}}"},
            }
            test_name = operation_id or f"openapi-{str(method).lower()}-{path}"
            test_item: Dict[str, Any] = {
                "name": test_name,
                "request": request_spec,
            }

            raw_expectation = expectation_map.get(operation_id)
            if isinstance(raw_expectation, list):
                test_item["expectations"] = {"allowed_users": [str(u) for u in raw_expectation]}
            elif isinstance(raw_expectation, dict):
                allowed_users = raw_expectation.get("allowed_users")
                if isinstance(allowed_users, list):
                    test_item["expectations"] = {"allowed_users": [str(u) for u in allowed_users]}

            tests.append(test_item)
    return tests


def apply_prompt_instruction_defaults(config: Dict[str, Any]) -> Dict[str, Any]:
    prompt = str(config.get("instruction_prompt", "")).strip()
    inferred = _extract_prompt_instruction(prompt) if prompt else {}

    if prompt:
        users = config.get("users", [])
        expected_count = inferred.get("users_count")
        if expected_count is not None and expected_count != len(users):
            provided_count = len(users)
            provided_label = "user" if provided_count == 1 else "users"
            raise ValueError(
                f"instruction_prompt expects {expected_count} users but 'users' field contains {provided_count} {provided_label}"
            )

    # Login-sequence derivation needs the natural-language prompt (LLM or regex);
    # without one, callers supply an explicit login_sequence or per-user headers.
    if prompt and not config.get("login_sequence"):
        user_variable_names = list({
            key
            for user in config.get("users", [])
            for key in user.get("variables", {}).keys()
        })
        llm_sequence = _generate_login_sequence_with_ollama(prompt, user_variable_names, config)
        if llm_sequence is not None:
            config["login_sequence"] = llm_sequence
        else:
            config["login_sequence"] = _build_login_sequence_from_prompt(
                inferred.get("login_target", ""),
                inferred.get("app_target", ""),
            )

    if not config.get("authorization_tests"):
        openapi_spec = _load_openapi_spec(config)
        if openapi_spec:
            path_param_default = str(config.get("openapi_path_param_default", "1"))
            path_param_defaults = config.get("openapi_path_param_defaults", {})
            operation_path_param_defaults = config.get("openapi_operation_path_param_defaults", {})
            exclude_operation_ids = config.get("openapi_exclude_operation_ids", [])
            expectation_overrides = config.get("openapi_expectation_overrides", {})
            config["authorization_tests"] = _build_authorization_tests_from_openapi(
                openapi_spec,
                path_param_default=path_param_default,
                path_param_defaults=path_param_defaults if isinstance(path_param_defaults, dict) else {},
                operation_path_param_defaults=operation_path_param_defaults
                if isinstance(operation_path_param_defaults, dict)
                else {},
                exclude_operation_ids=exclude_operation_ids if isinstance(exclude_operation_ids, list) else [],
                expectation_overrides=expectation_overrides if isinstance(expectation_overrides, dict) else {},
            )
        else:
            has_burp_history = "burp_history_requests" in config
            has_burp_mcp_history = "burp_mcp_history_requests" in config
            if has_burp_history and has_burp_mcp_history:
                raise ValueError("Provide only one of burp_history_requests or burp_mcp_history_requests, not both")
            history_requests = config.get("burp_history_requests", []) or config.get("burp_mcp_history_requests", [])
            if history_requests:
                config["authorization_tests"] = _build_authorization_tests_from_burp_history(history_requests)
            elif inferred.get("verify_burp_history"):
                raise ValueError(
                    "instruction_prompt requests Burp history verification but no history requests were provided"
                )

    return config


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        if path.endswith(".yaml") or path.endswith(".yml"):
            try:
                import yaml
            except ImportError as exc:
                raise ValueError(
                    "YAML configs require PyYAML (pip install pyyaml); "
                    "use a JSON config to stay dependency-free"
                ) from exc
            config = yaml.safe_load(f)
        else:
            config = json.load(f)
    return apply_prompt_instruction_defaults(config)


def choose_executor(config: Dict[str, Any]) -> RequestExecutor:
    timeout_seconds = float(config.get("http_timeout_seconds", 20))
    burp_url = config.get("burp_mcp_url")
    if burp_url:
        return BurpMCPExecutor(burp_url, timeout_seconds=timeout_seconds)
    ssl_verify = bool(config.get("ssl_verify", True))
    ca_bundle_path = str(config.get("target_ca_bundle_path", "")).strip()
    return DirectHTTPExecutor(timeout_seconds=timeout_seconds, ssl_verify=ssl_verify, ca_bundle_path=ca_bundle_path)


def generate_report(config: Dict[str, Any]) -> Dict[str, Any]:
    executor = choose_executor(config)
    user_contexts = authenticate_users(config, executor)
    findings = run_authorization_tests(config, user_contexts, executor)
    findings = llm_analyze_findings(findings, config)
    report = {
        "users_tested": [u["name"] for u in config.get("users", [])],
        "findings": findings,
    }
    report.update(maybe_generate_llm_summary(config, report))
    return report


_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_SARIF_RULES = [
    {"id": "IDOR-001", "name": "BrokenAccessControl",
     "shortDescription": {"text": "Possible IDOR or broken access control"},
     "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
     "defaultConfiguration": {"level": "error"}},
    {"id": "IDOR-002", "name": "IdenticalUnauthorizedAccess",
     "shortDescription": {"text": "Possible IDOR: all users received identical successful responses"},
     "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
     "defaultConfiguration": {"level": "warning"}},
    {"id": "IDOR-003", "name": "CrossUserDataLeak",
     "shortDescription": {"text": "Possible cross-user data leak: all users succeeded but with different content"},
     "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
     "defaultConfiguration": {"level": "warning"}},
    {"id": "IDOR-004", "name": "StatefulTestOrMissingFixture",
     "shortDescription": {"text": "Possible stateful test or missing fixture"},
     "defaultConfiguration": {"level": "warning"}},
    {"id": "IDOR-005", "name": "UnexpectedAuthorizationBehavior",
     "shortDescription": {"text": "Unexpected authorization or application behavior"},
     "defaultConfiguration": {"level": "warning"}},
    {"id": "IDOR-000", "name": "AuthorizationBehaviorObserved",
     "shortDescription": {"text": "Authorization behavior observed (informational)"},
     "defaultConfiguration": {"level": "note"}},
]

_FINDING_TO_RULE = {
    "possible_idor_or_broken_access_control": "IDOR-001",
    "possible_idor_identical_successful_access": "IDOR-002",
    "possible_cross_user_data_leak": "IDOR-003",
    "possible_stateful_test_or_missing_fixture": "IDOR-004",
    "unexpected_authorization_or_application_behavior": "IDOR-005",
    "authorization_behavior_observed": "IDOR-000",
}

_RISK_TO_SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def _sarif_source_uri(config_path: str) -> str:
    """Return a checkout-relative POSIX path for SARIF artifactLocation, or "".

    GitHub code scanning rejects absolute or http(s) artifact URIs because it
    can only relativize file paths against the repository checkout. A DAST
    finding has no source file, so results are anchored to the config that
    declared the tests (the live endpoint URL lives in the message/properties).
    """
    if not config_path:
        return ""
    try:
        rel = os.path.relpath(config_path)
    except ValueError:
        return ""
    rel = rel.replace(os.sep, "/")
    if rel == ".." or rel.startswith("../"):
        return ""
    return rel


def generate_sarif_report(report: Dict[str, Any], source_uri: str = "") -> Dict[str, Any]:
    results = []
    for finding in report.get("findings", []):
        rule_id = _FINDING_TO_RULE.get(finding.get("finding", ""), "IDOR-000")
        level = _RISK_TO_SARIF_LEVEL.get(finding.get("risk", "low"), "note")
        method = finding.get("request_method", "")
        url = finding.get("request_url", "")
        test_name = finding.get("test", "")
        notes = finding.get("notes", [])
        details_lines = [
            f"{user}: HTTP {data['status']}"
            for user, data in finding.get("details", {}).items()
        ]
        message_parts = [finding.get("finding", "")] + notes + details_lines
        message_text = " | ".join(p for p in message_parts if p)

        location: Dict[str, Any] = {
            "logicalLocations": [
                {
                    "name": test_name,
                    "fullyQualifiedName": f"{method} {url}".strip(),
                    "kind": "member",
                }
            ]
        }
        # Anchor to a checkout-relative file (the config) so code scanning can
        # ingest it; the live http(s) endpoint is kept in properties/message.
        if source_uri:
            location["physicalLocation"] = {"artifactLocation": {"uri": source_uri}}

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [location],
            "properties": {
                "risk": finding.get("risk"),
                "finding": finding.get("finding"),
                "endpoint": f"{method} {url}".strip(),
                "users_tested": list(finding.get("details", {}).keys()),
            },
        })

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "iDOR-Scanner",
                        "informationUri": "https://github.com/swiru95/iDOR-Scanner",
                        "rules": _SARIF_RULES,
                    }
                },
                "results": results,
            }
        ],
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Autonomous iDOR scanner for multi-user authorization checks")
    parser.add_argument("--config", required=True, help="Path to JSON configuration")
    parser.add_argument("--instruction", help="Optional natural-language instruction prompt")
    parser.add_argument("--output", help="Optional output file path for report JSON")
    parser.add_argument("--output-sarif", help="Optional output file path for SARIF report")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    if args.instruction:
        config["instruction_prompt"] = args.instruction
        config = apply_prompt_instruction_defaults(config)
    report = generate_report(config)

    rendered = json.dumps(report, indent=2)
    print(rendered)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(rendered + "\n")
    if args.output_sarif:
        sarif = generate_sarif_report(report, source_uri=_sarif_source_uri(args.config))
        with open(args.output_sarif, "w", encoding="utf-8") as f:
            f.write(json.dumps(sarif, indent=2) + "\n")
    has_high_risk = any(f.get("risk") == "high" for f in report.get("findings", []))
    return 1 if has_high_risk else 0


if __name__ == "__main__":
    sys.exit(main())
