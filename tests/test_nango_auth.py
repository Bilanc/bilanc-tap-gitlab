import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import requests

from tap_gitlab import auth
from tap_gitlab.auth import GitlabAuth


def response(status, body=None, reason=None):
    result = requests.Response()
    result.status_code = status
    result.reason = reason
    if body is not None:
        result._content = json.dumps(body).encode()
    else:
        result._content = b""
    return result


def expires_in(**kwargs):
    return (datetime.now(timezone.utc) + timedelta(**kwargs)).strftime(
        auth.NANGO_EXPIRES_AT_FORMAT
    )


def ok_response(token="new-token", expires_at=None):
    return response(
        200,
        {
            "end_user": {"email": "someone@example.com", "display_name": "Someone"},
            "credentials": {
                "access_token": token,
                "expires_at": expires_at or expires_in(hours=2),
            },
        },
    )


def refresh_error(code="invalid_credentials",
                  message="The external API returned an error when trying to refresh the access token."):
    return response(400, {"error": {"code": code, "message": message}})


class NangoAuthTests(unittest.TestCase):
    def setUp(self):
        # also makes backoff instantaneous (same time.sleep)
        self.sleep_patch = mock.patch("tap_gitlab.auth.time.sleep", return_value=None)
        self.sleep = self.sleep_patch.start()
        self.session_patch = mock.patch("tap_gitlab.auth.requests.Session")
        self.session = self.session_patch.start().return_value
        fd, self.config_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)

    def tearDown(self):
        os.remove(self.config_path)
        self.session_patch.stop()
        self.sleep_patch.stop()

    def make_auth(self, **extra):
        config = {"nango_connection_id": "conn-1", "nango_secret_key": "secret"}
        config.update(extra)
        with open(self.config_path, "w") as f:
            json.dump(config, f)
        return GitlabAuth(self.config_path)

    def urls(self):
        return [call.args[0] for call in self.session.get.call_args_list]

    def test_success_uses_force_refresh_and_caches_token(self):
        self.session.get.return_value = ok_response()
        gitlab_auth = self.make_auth()

        self.assertEqual(gitlab_auth.get_auth_token(), "new-token")
        self.assertEqual(gitlab_auth.get_auth_token(), "new-token")

        self.assertEqual(self.session.get.call_count, 1)
        self.assertIn("provider_config_key=gitlab&force_refresh=true", self.urls()[0])
        self.assertEqual(self.session.get.call_args.kwargs["timeout"], auth.NANGO_REQUEST_TIMEOUT)
        self.sleep.assert_not_called()

    def test_self_hosted_uses_pat_integration(self):
        self.session.get.return_value = response(200, {"credentials": {"apiKey": "glpat-x"}})
        gitlab_auth = self.make_auth(self_hosted=True)

        self.assertEqual(gitlab_auth.get_auth_token(), "glpat-x")
        self.assertEqual(gitlab_auth.get_auth_token(), "glpat-x")
        self.assertEqual(self.session.get.call_count, 1)
        self.assertIn("provider_config_key=gitlab-pat", self.urls()[0])

    def test_400_on_force_refresh_retries_once_without_force_refresh(self):
        self.session.get.side_effect = [refresh_error(), ok_response(token="held-token")]

        self.assertEqual(self.make_auth().get_auth_token(), "held-token")

        urls = self.urls()
        self.assertEqual(len(urls), 2)
        self.assertIn("force_refresh=true", urls[0])
        self.assertNotIn("force_refresh", urls[1])
        self.sleep.assert_called_once_with(auth.NANGO_FORCE_REFRESH_RETRY_DELAY)

    def test_400_fallback_token_expiring_within_margin_is_rejected(self):
        self.session.get.side_effect = [
            refresh_error(),
            ok_response(token="held-token", expires_at=expires_in(minutes=10)),
        ]

        with self.assertRaises(auth.NangoRefreshError) as ctx:
            self.make_auth().get_auth_token()

        self.assertEqual(self.session.get.call_count, 2)
        self.assertIn("invalid_credentials: The external API returned an error", str(ctx.exception))
        self.assertIn("too soon to use", str(ctx.exception))
        self.assertIn("400", str(ctx.exception))

    def test_400_twice_raises_error_details_without_connection_payload(self):
        self.session.get.side_effect = [
            refresh_error(),
            response(400, {
                "error": {"code": "invalid_credentials", "message": "token revoked"},
                "end_user": {"email": "someone@example.com"},
            }),
        ]

        with self.assertRaises(auth.NangoRefreshError) as ctx:
            self.make_auth().get_auth_token()

        message = str(ctx.exception)
        self.assertEqual(self.session.get.call_count, 2)
        self.assertIn("invalid_credentials: token revoked", message)
        self.assertIn("conn-1", message)
        self.assertNotIn("someone@example.com", message)

    def test_401_is_not_retried(self):
        self.session.get.return_value = response(
            401, {"error": {"code": "invalid_secret_key", "message": "bad key"}})

        with self.assertRaises(auth.NangoRefreshError) as ctx:
            self.make_auth().get_auth_token()

        self.assertEqual(self.session.get.call_count, 1)
        self.assertIn("401", str(ctx.exception))
        self.assertIn("invalid_secret_key: bad key", str(ctx.exception))
        self.sleep.assert_not_called()

    def test_5xx_is_retried_then_succeeds(self):
        self.session.get.side_effect = [
            response(503, reason="Service Temporarily Unavailable"),
            response(504, reason="Gateway Time-out"),
            ok_response(),
        ]

        self.assertEqual(self.make_auth().get_auth_token(), "new-token")
        self.assertEqual(self.session.get.call_count, 3)
        self.assertTrue(all("force_refresh=true" in url for url in self.urls()))

    def test_5xx_gives_up_after_max_tries(self):
        self.session.get.return_value = response(503, reason="Service Temporarily Unavailable")

        with self.assertRaises(auth.NangoServerError) as ctx:
            self.make_auth().get_auth_token()

        self.assertEqual(self.session.get.call_count, auth.NANGO_MAX_TRIES)
        self.assertIn("503", str(ctx.exception))
        self.assertIn("Service Temporarily Unavailable", str(ctx.exception))

    def test_429_is_retried_after_retry_after(self):
        limited = response(429, reason="Too Many Requests")
        limited.headers["Retry-After"] = "7"
        self.session.get.side_effect = [limited, ok_response()]

        self.assertEqual(self.make_auth().get_auth_token(), "new-token")
        self.assertEqual(self.session.get.call_count, 2)
        self.sleep.assert_any_call(7)

    def test_429_gives_up_after_max_tries(self):
        limited = response(429, reason="Too Many Requests")
        limited.headers["Retry-After"] = "60"
        self.session.get.return_value = limited

        with self.assertRaises(auth.NangoServerError) as ctx:
            self.make_auth().get_auth_token()

        self.assertEqual(self.session.get.call_count, auth.NANGO_MAX_TRIES)
        self.assertIn("429", str(ctx.exception))

    def test_negative_retry_after_is_clamped(self):
        limited = response(429, reason="Too Many Requests")
        limited.headers["Retry-After"] = "-3"
        self.session.get.side_effect = [limited, ok_response()]

        self.assertEqual(self.make_auth().get_auth_token(), "new-token")
        self.assertEqual(self.session.get.call_count, 2)
        self.sleep.assert_any_call(0)

    def test_timeout_connection_and_chunked_encoding_errors_are_retried(self):
        self.session.get.side_effect = [
            requests.Timeout("timed out"),
            requests.ConnectionError("reset"),
            requests.exceptions.ChunkedEncodingError("Connection broken"),
            ok_response(),
        ]

        self.assertEqual(self.make_auth().get_auth_token(), "new-token")
        self.assertEqual(self.session.get.call_count, 4)

    def test_stale_token_is_refreshed_on_next_request(self):
        self.session.get.side_effect = [
            ok_response(token="first", expires_at=expires_in(minutes=25)),
            ok_response(token="second"),
        ]
        gitlab_auth = self.make_auth()

        self.assertEqual(gitlab_auth.get_auth_token(), "first")
        with mock.patch("tap_gitlab.auth.datetime") as dt:
            dt.now.return_value = datetime.now(timezone.utc) + timedelta(minutes=6)
            dt.strptime = datetime.strptime
            dt.max = datetime.max
            self.assertEqual(gitlab_auth.get_auth_token(), "second")
        self.assertEqual(self.session.get.call_count, 2)



class OutlivesMarginTests(unittest.TestCase):
    def test_margin_is_twenty_minutes(self):
        self.assertEqual(auth.NANGO_EXPIRY_MARGIN, timedelta(minutes=20))

    def test_boundaries(self):
        self.assertFalse(auth._outlives_margin(None))
        self.assertTrue(auth._outlives_margin(expires_in(minutes=21)))
        self.assertFalse(auth._outlives_margin(expires_in(minutes=19)))
        self.assertFalse(auth._outlives_margin(expires_in(minutes=-5)))
        self.assertFalse(auth._outlives_margin("not-a-date"))


class NangoErrorDetailsTests(unittest.TestCase):
    def test_list_error_body_is_not_echoed(self):
        resp = response(400, {"error": ["token=secret"]})
        self.assertEqual(auth.nango_error_details(resp), "HTTP 400")

    def test_prefers_code_and_message(self):
        self.assertEqual(
            auth.nango_error_details(refresh_error(message="nope")),
            "invalid_credentials: nope",
        )

    def test_string_error(self):
        self.assertEqual(
            auth.nango_error_details(response(400, {"error": "Bad Request"})), "Bad Request")

    def test_non_json_body_falls_back_to_reason_without_leaking_body(self):
        resp = requests.Response()
        resp.status_code = 503
        resp.reason = "Service Temporarily Unavailable"
        resp._content = b"<html><body>nginx</body></html>"
        self.assertEqual(auth.nango_error_details(resp), "Service Temporarily Unavailable")

    def test_connection_payload_without_error_is_not_echoed(self):
        resp = response(400, {"end_user": {"email": "someone@example.com"}}, reason="Bad Request")
        self.assertEqual(auth.nango_error_details(resp), "Bad Request")


if __name__ == "__main__":
    unittest.main()
