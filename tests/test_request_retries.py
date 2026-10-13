import unittest
from unittest import mock

import tap_gitlab


class FakeAuth:
    def get_auth_token(self):
        return "token"


def make_response(status_code, content=b"", headers=None):
    resp = mock.Mock()
    resp.status_code = status_code
    resp.content = content
    resp.headers = headers or {}
    resp.json.return_value = []
    return resp


HTML_503 = b"\n<!DOCTYPE html>\n<html>\n<head>\n  <title>503 Server Unavailable</title>\n  <style>\n" + b"body { color: #666; }\n" * 50


class RequestRetryTests(unittest.TestCase):
    def setUp(self):
        self.auth_patch = mock.patch.object(tap_gitlab, "AUTH", FakeAuth())
        self.auth_patch.start()
        self.session_patch = mock.patch.object(tap_gitlab, "SESSION")
        self.session = self.session_patch.start()
        # make backoff instantaneous
        self.sleep_patch = mock.patch("backoff._sync.time.sleep")
        self.sleep_patch.start()

    def tearDown(self):
        self.sleep_patch.stop()
        self.session_patch.stop()
        self.auth_patch.stop()

    def test_503_and_504_are_retried_then_succeed(self):
        ok = make_response(200)
        self.session.request.side_effect = [
            make_response(503, HTML_503),
            make_response(504, b"Gateway Time-out"),
            ok,
        ]
        resp = tap_gitlab.request("https://gitlab.com/api/v4/projects/1/repository/tags")
        self.assertIs(resp, ok)
        self.assertEqual(self.session.request.call_count, 3)

    def test_persistent_503_gives_up_after_max_tries(self):
        self.session.request.side_effect = [make_response(503, HTML_503)] * 10
        with self.assertRaises(tap_gitlab.RetriableAPIError) as ctx:
            tap_gitlab.request("https://gitlab.com/api/v4/projects/1/users")
        self.assertEqual(self.session.request.call_count, 5)
        message = str(ctx.exception)
        self.assertIn("[503 - ", message)
        self.assertIn("503 Server Unavailable", message)
        self.assertLess(len(message), 500)

    def test_non_retriable_error_is_raised_once_with_truncated_body(self):
        self.session.request.side_effect = [make_response(422, HTML_503)]
        with self.assertRaises(Exception) as ctx:
            tap_gitlab.request("https://gitlab.com/api/v4/projects/1/users")
        self.assertEqual(self.session.request.call_count, 1)
        message = str(ctx.exception)
        self.assertIn("[422 - ", message)
        self.assertIn("503 Server Unavailable", message)
        self.assertLess(len(message), 500)

    def test_truncate_body(self):
        self.assertEqual(tap_gitlab.truncate_body(b"short body"), "short body")
        long_body = "x" * (tap_gitlab.ERROR_BODY_MAX_CHARS + 10)
        self.assertEqual(
            tap_gitlab.truncate_body(long_body),
            "x" * tap_gitlab.ERROR_BODY_MAX_CHARS + "...",
        )


if __name__ == "__main__":
    unittest.main()
