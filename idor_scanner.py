#!/usr/bin/env python3
import argparse
import base64
import copy
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


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
    def send(self, request_spec: Dict[str, Any]) -> HTTPResult:
        method = request_spec.get("method", "GET").upper()
        url = request_spec["url"]
        headers = {k: str(v) for k, v in request_spec.get("headers", {}).items()}
        body_data = _encode_body(request_spec, headers)
        req = urllib.request.Request(url=url, data=body_data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return HTTPResult(status=resp.status, headers=dict(resp.headers.items()), body=body)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return HTTPResult(status=e.code, headers=dict(e.headers.items()), body=body)


class BurpMCPExecutor(RequestExecutor):
    def __init__(self, burp_mcp_url: str):
        self.burp_mcp_url = burp_mcp_url

    def send(self, request_spec: Dict[str, Any]) -> HTTPResult:
        payload = json.dumps({"request": request_spec}).encode("utf-8")
        req = urllib.request.Request(
            self.burp_mcp_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
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
    if key in context:
        return "" if context[key] is None else str(context[key])
    if "." not in key:
        return ""
    nested = _read_json_path(context, key)
    return nested


def render_template(value: Any, context: Dict[str, Any]) -> Any:
    if isinstance(value, str):
        return re.sub(r"\{\{\s*([a-zA-Z0-9_\.\-]+)\s*\}\}", lambda m: _lookup_context_value(context, m.group(1)), value)
    if isinstance(value, dict):
        return {k: render_template(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [render_template(v, context) for v in value]
    return value


def extract_value(result: HTTPResult, rule: Dict[str, str]) -> str:
    source = rule.get("from", "json")
    if source == "header":
        return result.headers.get(rule["name"], "")
    if source == "regex":
        match = re.search(rule["pattern"], result.body)
        return match.group(1) if match else ""
    json_payload = json.loads(result.body or "{}")
    return _read_json_path(json_payload, rule.get("path", ""))


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
            "body_preview": result.body[:180],
        }
        for user, result in user_results.items()
    }

    finding = "authorization_behavior_observed"
    risk = "low"

    if expectations:
        allowed = set(expectations.get("allowed_users", []))
        violations = []
        for user, result in user_results.items():
            is_success = 200 <= result.status < 300
            if user in allowed and not is_success:
                violations.append(f"{user} should be allowed but got {result.status}")
            if user not in allowed and is_success:
                violations.append(f"{user} should not be allowed but got {result.status}")
        if violations:
            finding = "possible_idor_or_authz_misconfiguration"
            risk = "high"
        notes = violations
    else:
        statuses = {r.status for r in user_results.values()}
        hashes = {r.body_hash for r in user_results.values()}
        all_success = all(200 <= r.status < 300 for r in user_results.values())
        if len(user_results) > 1 and len(statuses) == 1 and len(hashes) == 1 and all_success:
            finding = "possible_idor_identical_successful_access"
            risk = "medium"
            notes = ["All tested users received successful and identical responses."]
        else:
            notes = ["Differences detected or non-success responses observed."]

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
    user_contexts: Dict[str, Dict[str, Any]] = {}

    for user in config.get("users", []):
        user_name = user["name"]
        context = {**shared, **user.get("variables", {})}
        for step in sequence:
            request_spec = render_template(copy.deepcopy(step["request"]), context)
            result = executor.send(request_spec)
            for target, rule in step.get("extract", {}).items():
                context[target] = extract_value(result, rule)
        user_contexts[user_name] = context
    return user_contexts


def run_authorization_tests(config: Dict[str, Any], user_contexts: Dict[str, Dict[str, Any]], executor: RequestExecutor) -> List[Dict[str, Any]]:
    findings = []
    for test in config.get("authorization_tests", []):
        per_user_results: Dict[str, HTTPResult] = {}
        for user in config.get("users", []):
            user_name = user["name"]
            context = {**user_contexts[user_name], **test.get("variables", {})}
            request_spec = render_template(copy.deepcopy(test["request"]), context)
            per_user_results[user_name] = executor.send(request_spec)
        findings.append(
            evaluate_test_results(
                test_name=test.get("name", "unnamed_test"),
                user_results=per_user_results,
                expectations=test.get("expectations"),
            )
        )
    return findings


def maybe_generate_llm_summary(config: Dict[str, Any], report: Dict[str, Any]) -> Optional[str]:
    model = config.get("ollama_model")
    base_url = config.get("ollama_url")
    if not model or not base_url:
        return None

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
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response")
    except Exception:
        return None


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def choose_executor(config: Dict[str, Any]) -> RequestExecutor:
    burp_url = config.get("burp_mcp_url")
    if burp_url:
        return BurpMCPExecutor(burp_url)
    return DirectHTTPExecutor()


def generate_report(config: Dict[str, Any]) -> Dict[str, Any]:
    executor = choose_executor(config)
    user_contexts = authenticate_users(config, executor)
    findings = run_authorization_tests(config, user_contexts, executor)
    report = {
        "users_tested": [u["name"] for u in config.get("users", [])],
        "findings": findings,
    }
    llm_summary = maybe_generate_llm_summary(config, report)
    if llm_summary:
        report["llm_summary"] = llm_summary
    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Autonomous iDOR scanner for multi-user authorization checks")
    parser.add_argument("--config", required=True, help="Path to JSON configuration")
    parser.add_argument("--output", help="Optional output file path for report JSON")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    report = generate_report(config)

    rendered = json.dumps(report, indent=2)
    print(rendered)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(rendered + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
