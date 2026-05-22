import os
import unittest
import tempfile
import json

from idor_scanner import (
    BurpMCPExecutor,
    HTTPResult,
    apply_prompt_instruction_defaults,
    authenticate_users,
    evaluate_test_results,
    extract_value,
    generate_sarif_report,
    maybe_generate_llm_summary,
    render_template,
    run_authorization_tests,
)

_SEQUENTIAL = {"max_concurrent_requests": 1}


class FakeExecutor:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def send(self, request_spec):
        self.calls.append(request_spec)
        return self.responses[len(self.calls) - 1]


class TestIDORScannerHelpers(unittest.TestCase):
    def test_render_template_nested_values(self):
        payload = {
            "url": "https://example.com/users/{{ target_id }}",
            "headers": {"Authorization": "Bearer {{token}}"},
            "json": {"owner": "{{user}}"},
        }
        rendered = render_template(payload, {"target_id": 42, "token": "abc", "user": "alice"})
        self.assertEqual(rendered["url"], "https://example.com/users/42")
        self.assertEqual(rendered["headers"]["Authorization"], "Bearer abc")
        self.assertEqual(rendered["json"]["owner"], "alice")

    def test_extract_value_from_json_path(self):
        result = HTTPResult(status=200, headers={}, body='{"data": {"token": "t-123"}}')
        extracted = extract_value(result, {"from": "json", "path": "data.token"})
        self.assertEqual(extracted, "t-123")

    def test_extract_value_from_json_path_handles_non_json_body(self):
        result = HTTPResult(status=200, headers={}, body="not-json")
        extracted = extract_value(result, {"from": "json", "path": "data.token"})
        self.assertEqual(extracted, "")

    def test_render_template_supports_nested_path(self):
        rendered = render_template("Bearer {{user.token}}", {"user": {"token": "deep-token"}})
        self.assertEqual(rendered, "Bearer deep-token")

    def test_evaluate_heuristic_detects_identical_success(self):
        findings = evaluate_test_results(
            "same-response",
            {
                "alice": HTTPResult(200, {}, '{"id": 1}'),
                "bob": HTTPResult(200, {}, '{"id": 1}'),
            },
        )
        self.assertEqual(findings["finding"], "possible_idor_identical_successful_access")
        self.assertEqual(findings["risk"], "medium")

    def test_evaluate_expectation_flags_unauthorized_success(self):
        findings = evaluate_test_results(
            "expected-deny",
            {
                "admin": HTTPResult(200, {}, "ok"),
                "viewer": HTTPResult(200, {}, "ok"),
            },
            expectations={"allowed_users": ["admin"]},
        )
        self.assertEqual(findings["finding"], "possible_idor_or_broken_access_control")
        self.assertEqual(findings["risk"], "high")

    def test_evaluate_expectation_allowed_not_found_is_medium(self):
        findings = evaluate_test_results(
            "expected-allow-not-found",
            {
                "admin": HTTPResult(404, {}, "missing"),
                "viewer": HTTPResult(403, {}, "forbidden"),
            },
            expectations={"allowed_users": ["admin"]},
        )
        self.assertEqual(findings["finding"], "possible_stateful_test_or_missing_fixture")
        self.assertEqual(findings["risk"], "medium")

    def test_authenticate_users_and_run_authorization_tests(self):
        config = {
            **_SEQUENTIAL,
            "users": [
                {"name": "alice", "variables": {"username": "alice", "password": "pa"}},
                {"name": "bob", "variables": {"username": "bob", "password": "pb"}},
            ],
            "login_sequence": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://example.test/login",
                        "json": {"username": "{{username}}", "password": "{{password}}"},
                    },
                    "extract": {"access_token": {"from": "json", "path": "token"}},
                }
            ],
            "authorization_tests": [
                {
                    "name": "account-read",
                    "request": {
                        "method": "GET",
                        "url": "https://example.test/accounts/100",
                        "headers": {"Authorization": "Bearer {{access_token}}"},
                    },
                }
            ],
        }
        executor = FakeExecutor(
            [
                HTTPResult(200, {}, '{"token": "t-alice"}'),
                HTTPResult(200, {}, '{"token": "t-bob"}'),
                HTTPResult(200, {}, '{"owner":"alice"}'),
                HTTPResult(403, {}, "forbidden"),
            ]
        )

        user_contexts = authenticate_users(config, executor)
        findings = run_authorization_tests(config, user_contexts, executor)

        self.assertEqual(user_contexts["alice"]["access_token"], "t-alice")
        self.assertEqual(user_contexts["bob"]["access_token"], "t-bob")
        self.assertEqual(findings[0]["test"], "account-read")
        self.assertEqual(findings[0]["details"]["alice"]["status"], 200)
        self.assertEqual(findings[0]["details"]["bob"]["status"], 403)
        self.assertEqual(executor.calls[2]["headers"]["Authorization"], "Bearer t-alice")
        self.assertEqual(executor.calls[3]["headers"]["Authorization"], "Bearer t-bob")

    def test_authorization_with_per_user_headers_no_login(self):
        config = {
            **_SEQUENTIAL,
            "users": [
                {"name": "john", "variables": {}, "headers": {"Authorization": "Bearer X"}},
                {"name": "bob", "variables": {}, "headers": {"Authorization": "Bearer Y"}},
            ],
            "authorization_tests": [
                {
                    "name": "profile-read",
                    "request": {
                        "method": "GET",
                        "url": "https://example.test/profile/100",
                        "headers": {"Authorization": "Bearer {{access_token}}"},
                    },
                }
            ],
        }
        executor = FakeExecutor(
            [
                HTTPResult(200, {}, '{"owner":"john"}'),
                HTTPResult(403, {}, "forbidden"),
            ]
        )

        user_contexts = authenticate_users(config, executor)
        findings = run_authorization_tests(config, user_contexts, executor)

        self.assertEqual(user_contexts["john"], {})
        self.assertEqual(user_contexts["bob"], {})
        self.assertEqual(findings[0]["details"]["john"]["status"], 200)
        self.assertEqual(findings[0]["details"]["bob"]["status"], 403)
        self.assertEqual(executor.calls[0]["headers"]["Authorization"], "Bearer X")
        self.assertEqual(executor.calls[1]["headers"]["Authorization"], "Bearer Y")

    def test_apply_prompt_instruction_defaults_derives_login_and_tests(self):
        config = {
            "instruction_prompt": (
                "Hi, go to login.example.com and use username/password to obtain token for app.example.com, "
                "use these 2 users to test given in burp history requests"
            ),
            "users": [
                {"name": "alice", "variables": {"username": "alice", "password": "a-pass"}},
                {"name": "bob", "variables": {"username": "bob", "password": "b-pass"}},
            ],
            "burp_history_requests": [
                {"method": "GET", "url": "https://app.example.com/api/account/1"},
                {"method": "GET", "url": "https://app.example.com/api/account/2"},
            ],
        }
        rendered = apply_prompt_instruction_defaults(config)

        self.assertEqual(rendered["login_sequence"][0]["request"]["url"], "https://login.example.com/login")
        self.assertEqual(rendered["login_sequence"][0]["request"]["json"]["audience"], "https://app.example.com")
        self.assertEqual(len(rendered["authorization_tests"]), 2)
        self.assertEqual(
            rendered["authorization_tests"][0]["request"]["headers"]["Authorization"],
            "Bearer {{access_token}}",
        )

    def test_apply_prompt_instruction_defaults_rejects_user_count_mismatch(self):
        config = {
            "instruction_prompt": "go to login.example.com obtain token for app.example.com use these 3 users",
            "users": [{"name": "only-one", "variables": {}}],
        }
        with self.assertRaisesRegex(ValueError, "expects 3 users but 'users' field contains 1 user"):
            apply_prompt_instruction_defaults(config)

    def test_apply_prompt_instruction_defaults_derives_tests_from_openapi_spec(self):
        config = {
            "instruction_prompt": "go to login.example.com and obtain token for app.example.com use these 1 users",
            "users": [{"name": "alice", "variables": {"username": "alice", "password": "secret"}}],
            "openapi_spec": {
                "servers": [{"url": "https://app.example.com"}],
                "paths": {
                    "/api/accounts/{id}": {
                        "get": {"operationId": "getAccount"},
                        "patch": {},
                    }
                },
            },
        }

        rendered = apply_prompt_instruction_defaults(config)

        self.assertEqual(len(rendered["authorization_tests"]), 2)
        self.assertEqual(rendered["authorization_tests"][0]["name"], "getAccount")
        self.assertEqual(
            rendered["authorization_tests"][0]["request"]["url"],
            "https://app.example.com/api/accounts/1",
        )
        self.assertEqual(
            rendered["authorization_tests"][1]["request"]["headers"]["Authorization"],
            "Bearer {{access_token}}",
        )

    def test_apply_prompt_instruction_defaults_loads_openapi_spec_from_path(self):
        spec = {
            "servers": [{"url": "https://api.example.com"}],
            "paths": {"/users": {"get": {}}},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp_file:
            json.dump(spec, tmp_file)
            tmp_path = tmp_file.name
        try:
            config = {
                "instruction_prompt": "go to login.example.com and obtain token for app.example.com use these 1 users",
                "users": [{"name": "alice", "variables": {"username": "alice", "password": "secret"}}],
                "openapi_spec_path": tmp_path,
            }
            rendered = apply_prompt_instruction_defaults(config)
            self.assertEqual(rendered["authorization_tests"][0]["request"]["url"], "https://api.example.com/users")
        finally:
            os.unlink(tmp_path)

    def test_apply_prompt_instruction_defaults_requires_burp_history_when_prompt_demands_it(self):
        config = {
            "instruction_prompt": "verify all requests from burp MCP history",
            "users": [{"name": "alice", "variables": {}}],
        }
        with self.assertRaisesRegex(ValueError, "Burp history verification"):
            apply_prompt_instruction_defaults(config)

    def test_apply_prompt_instruction_defaults_rejects_dual_openapi_sources(self):
        config = {
            "instruction_prompt": "go to login.example.com and obtain token for app.example.com use these 1 users",
            "users": [{"name": "alice", "variables": {"username": "alice", "password": "secret"}}],
            "openapi_spec": {"paths": {"/users": {"get": {}}}},
            "openapi_spec_path": "/tmp/should-not-be-used.json",
        }
        with self.assertRaisesRegex(ValueError, "Provide only one of openapi_spec or openapi_spec_path"):
            apply_prompt_instruction_defaults(config)

    def test_apply_prompt_instruction_defaults_rejects_dual_burp_history_sources(self):
        config = {
            "instruction_prompt": "go to login.example.com and obtain token for app.example.com use these 1 users",
            "users": [{"name": "alice", "variables": {"username": "alice", "password": "secret"}}],
            "burp_history_requests": [{"method": "GET", "url": "https://app.example.com/a"}],
            "burp_mcp_history_requests": [{"method": "GET", "url": "https://app.example.com/b"}],
        }
        with self.assertRaisesRegex(
            ValueError,
            "Provide only one of burp_history_requests or burp_mcp_history_requests",
        ):
            apply_prompt_instruction_defaults(config)

    def test_apply_prompt_instruction_defaults_supports_openapi_path_param_default(self):
        config = {
            "instruction_prompt": "go to login.example.com and obtain token for app.example.com use these 1 users",
            "users": [{"name": "alice", "variables": {"username": "alice", "password": "secret"}}],
            "openapi_path_param_default": "999",
            "openapi_spec": {
                "servers": [{"url": "https://app.example.com"}],
                "paths": {"/users/{userId}/posts/{postId}": {"get": {}}},
            },
        }
        rendered = apply_prompt_instruction_defaults(config)
        self.assertEqual(
            rendered["authorization_tests"][0]["request"]["url"],
            "https://app.example.com/users/999/posts/999",
        )

    def test_apply_prompt_instruction_defaults_supports_openapi_named_and_operation_defaults(self):
        config = {
            "instruction_prompt": "go to login.example.com and obtain token for app.example.com use these 1 users",
            "users": [{"name": "alice", "variables": {"username": "alice", "password": "secret"}}],
            "openapi_path_param_default": "fallback",
            "openapi_path_param_defaults": {
                "report_id": "report-admin-finance",
            },
            "openapi_operation_path_param_defaults": {
                "deleteProject": {"project_id": "project-beta"},
            },
            "openapi_exclude_operation_ids": ["login"],
            "openapi_spec": {
                "servers": [{"url": "https://app.example.com"}],
                "paths": {
                    "/auth/login": {"post": {"operationId": "login"}},
                    "/api/reports/{report_id}": {"get": {"operationId": "getReport"}},
                    "/api/projects/{project_id}": {"delete": {"operationId": "deleteProject"}},
                },
            },
        }

        rendered = apply_prompt_instruction_defaults(config)
        tests = {t["name"]: t for t in rendered["authorization_tests"]}

        self.assertNotIn("login", tests)
        self.assertEqual(
            tests["getReport"]["request"]["url"],
            "https://app.example.com/api/reports/report-admin-finance",
        )
        self.assertEqual(
            tests["deleteProject"]["request"]["url"],
            "https://app.example.com/api/projects/project-beta",
        )

    def test_apply_prompt_instruction_defaults_supports_openapi_expectation_overrides(self):
        config = {
            "instruction_prompt": "go to login.example.com and obtain token for app.example.com use these 2 users",
            "users": [
                {"name": "admin_user", "variables": {"username": "admin_user", "password": "a"}},
                {"name": "viewer_user", "variables": {"username": "viewer_user", "password": "b"}},
            ],
            "openapi_expectation_overrides": {
                "getReport": ["admin_user"],
            },
            "openapi_spec": {
                "servers": [{"url": "https://app.example.com"}],
                "paths": {
                    "/api/reports/{report_id}": {
                        "get": {"operationId": "getReport"},
                    }
                },
            },
        }

        rendered = apply_prompt_instruction_defaults(config)
        self.assertEqual(rendered["authorization_tests"][0]["name"], "getReport")
        self.assertEqual(
            rendered["authorization_tests"][0]["expectations"]["allowed_users"],
            ["admin_user"],
        )

    def test_maybe_generate_llm_summary_missing_ca_bundle_path_returns_error(self):
        report = {"users_tested": ["alice"], "findings": []}
        result = maybe_generate_llm_summary(
            {
                "ollama_url": "https://ollama.kscsc.local",
                "ollama_model": "llama3.1",
                "ollama_ca_bundle_path": "/tmp/does-not-exist-ca.pem",
            },
            report,
        )
        self.assertIn("llm_summary_error", result)
        self.assertIn("ollama_ca_bundle_path does not exist", result["llm_summary_error"])

    def test_maybe_generate_llm_summary_without_llm_config_returns_empty(self):
        result = maybe_generate_llm_summary({}, {"users_tested": [], "findings": []})
        self.assertEqual(result, {})

    def test_generate_sarif_report_structure(self):
        report = {
            "users_tested": ["admin", "viewer"],
            "findings": [
                {
                    "test": "get-secret",
                    "finding": "possible_idor_or_broken_access_control",
                    "risk": "high",
                    "request_method": "GET",
                    "request_url": "https://example.test/api/secret/1",
                    "details": {
                        "admin": {"status": 200, "body_hash": "aaa", "body_preview": "ok"},
                        "viewer": {"status": 200, "body_hash": "bbb", "body_preview": "ok"},
                    },
                    "notes": ["viewer should not be allowed but got 200"],
                },
                {
                    "test": "get-profile",
                    "finding": "authorization_behavior_observed",
                    "risk": "low",
                    "request_method": "GET",
                    "request_url": "https://example.test/api/me/profile",
                    "details": {
                        "admin": {"status": 200, "body_hash": "ccc", "body_preview": "ok"},
                        "viewer": {"status": 403, "body_hash": "ddd", "body_preview": "forbidden"},
                    },
                    "notes": [],
                },
            ],
        }
        sarif = generate_sarif_report(report)

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("$schema", sarif)
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "iDOR-Scanner")
        self.assertEqual(len(run["results"]), 2)

        high_result = run["results"][0]
        self.assertEqual(high_result["ruleId"], "IDOR-001")
        self.assertEqual(high_result["level"], "error")
        self.assertIn("viewer should not be allowed", high_result["message"]["text"])
        self.assertEqual(
            high_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "https://example.test/api/secret/1",
        )
        self.assertEqual(
            high_result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"],
            "GET https://example.test/api/secret/1",
        )

        low_result = run["results"][1]
        self.assertEqual(low_result["ruleId"], "IDOR-000")
        self.assertEqual(low_result["level"], "note")

    def test_generate_sarif_report_risk_level_mapping(self):
        def _finding(risk, finding_type):
            return {
                "test": "t", "finding": finding_type, "risk": risk,
                "request_method": "GET", "request_url": "https://x.test/",
                "details": {}, "notes": [],
            }

        sarif = generate_sarif_report({"findings": [
            _finding("high", "possible_idor_or_broken_access_control"),
            _finding("medium", "possible_idor_identical_successful_access"),
            _finding("low", "authorization_behavior_observed"),
        ]})
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        self.assertEqual(levels, ["error", "warning", "note"])

    def test_run_authorization_tests_adds_request_url_and_method(self):
        config = {
            **_SEQUENTIAL,
            "users": [{"name": "alice", "variables": {}}],
            "authorization_tests": [
                {
                    "name": "check",
                    "request": {"method": "GET", "url": "https://example.test/api/data"},
                }
            ],
        }
        executor = FakeExecutor([HTTPResult(200, {}, '{"ok":true}')])
        user_contexts = authenticate_users(config, executor)
        findings = run_authorization_tests(config, user_contexts, executor)
        self.assertEqual(findings[0]["request_method"], "GET")
        self.assertEqual(findings[0]["request_url"], "https://example.test/api/data")

    def test_burp_mcp_executor_parses_http_response_from_tool_text(self):
        executor = BurpMCPExecutor("http://127.0.0.1:9876")
        text = (
            "HttpRequestResponse{httpRequest=GET / HTTP/1.1\r\nHost: x\r\n\r\n, "
            "httpResponse=HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            "X-Test: one\r\n\r\n{\"ok\":true}, messageAnnotations=Annotations{}}"
        )
        parsed = executor._parse_http_response_from_text(text)
        self.assertEqual(parsed.status, 200)
        self.assertEqual(parsed.headers["Content-Type"], "application/json")
        self.assertEqual(parsed.headers["X-Test"], "one")
        self.assertEqual(parsed.body, '{"ok":true}')

    def test_render_template_supports_env_variable(self):
        os.environ["IDOR_TEST_SECRET"] = "my-env-token"
        try:
            result = render_template("Bearer {{env.IDOR_TEST_SECRET}}", {})
            self.assertEqual(result, "Bearer my-env-token")
        finally:
            del os.environ["IDOR_TEST_SECRET"]

    def test_render_template_env_missing_variable_returns_empty(self):
        os.environ.pop("IDOR_MISSING_VAR", None)
        result = render_template("{{env.IDOR_MISSING_VAR}}", {})
        self.assertEqual(result, "")

    def test_extract_value_from_set_cookie(self):
        result = HTTPResult(
            status=200,
            headers={"Set-Cookie": "session=abc123; Path=/; HttpOnly"},
            body="",
        )
        extracted = extract_value(result, {"from": "set_cookie", "name": "session"})
        self.assertEqual(extracted, "abc123")

    def test_extract_value_from_set_cookie_missing_name_returns_empty(self):
        result = HTTPResult(status=200, headers={"Set-Cookie": "other=xyz"}, body="")
        extracted = extract_value(result, {"from": "set_cookie", "name": "session"})
        self.assertEqual(extracted, "")

    def test_evaluate_cross_user_data_leak_flags_different_successful_bodies(self):
        findings = evaluate_test_results(
            "different-bodies",
            {
                "alice": HTTPResult(200, {}, '{"owner": "alice", "ts": "t1"}'),
                "bob": HTTPResult(200, {}, '{"owner": "alice", "ts": "t2"}'),
            },
        )
        self.assertEqual(findings["finding"], "possible_cross_user_data_leak")
        self.assertEqual(findings["risk"], "medium")
        self.assertIn("full_body", findings["details"]["alice"])
        self.assertIn("full_body", findings["details"]["bob"])

    def test_evaluate_body_preview_length_is_500(self):
        long_body = "x" * 1000
        findings = evaluate_test_results(
            "long-body",
            {"alice": HTTPResult(200, {}, long_body)},
        )
        self.assertEqual(len(findings["details"]["alice"]["body_preview"]), 500)

    def test_burp_mcp_executor_builds_http1_content(self):
        executor = BurpMCPExecutor("http://127.0.0.1:9876")
        content = executor._build_http1_content(
            {
                "method": "POST",
                "url": "http://example.test:8080/path?a=1",
                "headers": {"X-Token": "abc"},
                "json": {"hello": "world"},
            }
        )
        self.assertEqual(content["targetHostname"], "example.test")
        self.assertEqual(content["targetPort"], 8080)
        self.assertFalse(content["usesHttps"])
        self.assertIn("POST /path?a=1 HTTP/1.1", content["content"])
        self.assertIn("Host: example.test:8080", content["content"])
        self.assertIn("X-Token: abc", content["content"])
        self.assertIn('\r\n\r\n{"hello": "world"}', content["content"])


if __name__ == "__main__":
    unittest.main()
