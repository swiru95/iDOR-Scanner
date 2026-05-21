import unittest

from idor_scanner import HTTPResult, evaluate_test_results, extract_value, render_template


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


if __name__ == "__main__":
    unittest.main()
