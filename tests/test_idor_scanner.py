import unittest

from idor_scanner import (
    HTTPResult,
    apply_prompt_instruction_defaults,
    authenticate_users,
    evaluate_test_results,
    extract_value,
    render_template,
    run_authorization_tests,
)


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
        self.assertEqual(findings["finding"], "possible_idor_or_authz_misconfiguration")
        self.assertEqual(findings["risk"], "high")

    def test_authenticate_users_and_run_authorization_tests(self):
        config = {
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
        with self.assertRaises(ValueError):
            apply_prompt_instruction_defaults(config)


if __name__ == "__main__":
    unittest.main()
