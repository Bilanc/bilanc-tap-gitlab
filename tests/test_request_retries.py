import datetime
import types
import unittest
from unittest import mock

import backoff
import requests

import tap_gitlab


class FakeClock:
    """Drives backoff's sleep and clock so max_time elapses instantly."""

    def __init__(self):
        self.now = datetime.datetime(2026, 10, 23, 6, 0, 0)
        self.sleeps = []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += datetime.timedelta(seconds=seconds)

    @property
    def elapsed(self):
        return sum(self.sleeps)

    def datetime_module(self):
        clock = self

        class _datetime:
            @staticmethod
            def now():
                return clock.now

        return types.SimpleNamespace(datetime=_datetime)

    def patches(self):
        return [mock.patch("backoff._sync.time.sleep", self.sleep),
                mock.patch("backoff._sync.datetime", self.datetime_module())]


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
        self.clock = FakeClock()
        self.clock_patches = self.clock.patches()
        for patch in self.clock_patches:
            patch.start()

    def tearDown(self):
        for patch in self.clock_patches:
            patch.stop()
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

    def test_persistent_503_gives_up_at_max_time(self):
        self.session.request.side_effect = lambda *a, **k: make_response(503, HTML_503)
        with self.assertRaises(tap_gitlab.RetriableAPIError) as ctx:
            tap_gitlab.request("https://gitlab.com/api/v4/projects/1/users")
        # backoff caps the last wait at the deadline, so the final attempt is
        # made at exactly REQUEST_MAX_TIME and at least every REQUEST_MAX_WAIT
        self.assertAlmostEqual(self.clock.elapsed, tap_gitlab.REQUEST_MAX_TIME, delta=0.01)
        self.assertGreaterEqual(
            self.session.request.call_count,
            tap_gitlab.REQUEST_MAX_TIME // tap_gitlab.REQUEST_MAX_WAIT + 1)
        self.assertLessEqual(max(self.clock.sleeps), tap_gitlab.REQUEST_MAX_WAIT)
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

    def test_outage_longer_than_five_tries_is_survived(self):
        # gitlab.zitec.com returned 503 for ~90 s; five tries gave up after ~25 s
        ok = make_response(200)
        self.session.request.side_effect = (
            [make_response(503, b'{"message":"503 Service Unavailable"}')] * 7 + [ok])
        resp = tap_gitlab.request("https://gitlab.com/api/v4/projects/2628/repository/tags")
        self.assertIs(resp, ok)
        self.assertEqual(self.session.request.call_count, 8)

    def test_outage_recovering_just_before_the_deadline_is_survived(self):
        # whatever jitter does to the individual waits, GitLab coming back at
        # 4m50s must still be seen before the 5 min window closes
        ok = make_response(200)
        recovery = tap_gitlab.REQUEST_MAX_TIME - 10

        def gitlab(*args, **kwargs):
            if self.clock.elapsed < recovery:
                return make_response(503, HTML_503)
            return ok

        self.session.request.side_effect = gitlab
        resp = tap_gitlab.request("https://gitlab.com/api/v4/projects/2628/repository/tags")
        self.assertIs(resp, ok)
        self.assertLessEqual(self.clock.elapsed, tap_gitlab.REQUEST_MAX_TIME + 0.01)

    def test_backoff_waits_are_capped(self):
        gen = backoff.expo(factor=2, max_value=tap_gitlab.REQUEST_MAX_WAIT)
        waits = [next(gen) for _ in range(12)]
        self.assertEqual(max(waits), tap_gitlab.REQUEST_MAX_WAIT)
        self.assertEqual(waits[:6], [2, 4, 8, 16, 32, 60])

    def test_connection_errors_are_retried_then_succeed(self):
        ok = make_response(200)
        self.session.request.side_effect = [
            requests.exceptions.ConnectionError("refused"),
            requests.exceptions.ReadTimeout("timed out"),
            ok,
        ]
        resp = tap_gitlab.request("https://gitlab.com/api/v4/projects/1/labels")
        self.assertIs(resp, ok)
        self.assertEqual(self.session.request.call_count, 3)

    def test_request_few_tries_keeps_the_short_window(self):
        self.session.request.side_effect = [make_response(500, b"Gitaly deadline")] * 20
        with self.assertRaises(tap_gitlab.RetriableAPIError):
            tap_gitlab.request_few_tries(
                "https://gitlab.com/api/v4/projects/1/repository/commits",
                {"with_stats": "true"})
        self.assertEqual(self.session.request.call_count, 5)

    def test_truncate_body(self):
        self.assertEqual(tap_gitlab.truncate_body(b"short body"), "short body")
        long_body = "x" * (tap_gitlab.ERROR_BODY_MAX_CHARS + 10)
        self.assertEqual(
            tap_gitlab.truncate_body(long_body),
            "x" * tap_gitlab.ERROR_BODY_MAX_CHARS + "...",
        )


class GiveUpOnStreamTests(unittest.TestCase):
    def setUp(self):
        self.auth_patch = mock.patch.object(tap_gitlab, "AUTH", FakeAuth())
        self.auth_patch.start()
        self.session_patch = mock.patch.object(tap_gitlab, "SESSION")
        self.session = self.session_patch.start()
        self.clock_patches = FakeClock().patches()
        for patch in self.clock_patches:
            patch.start()
        tap_gitlab.GIVE_UP_STREAK['count'] = 0

    def tearDown(self):
        tap_gitlab.GIVE_UP_STREAK['count'] = 0
        for patch in self.clock_patches:
            patch.stop()
        self.session_patch.stop()
        self.auth_patch.stop()

    @staticmethod
    def failing_stream(project):
        raise tap_gitlab.RetriableAPIError("tags [503 - Service Unavailable]")

    def test_full_refresh_stream_is_skipped_for_this_project(self):
        calls = []
        tap_gitlab.sync_full_refresh_stream(self.failing_stream, "tags", {"id": 2628})
        tap_gitlab.sync_full_refresh_stream(lambda p: calls.append(p["id"]), "tags", {"id": 2629})
        self.assertEqual(calls, [2629])
        self.assertEqual(tap_gitlab.GIVE_UP_STREAK['count'], 1)

    def test_repeated_give_ups_abort_the_sync(self):
        project = {"id": 2628}
        for _ in range(tap_gitlab.MAX_CONSECUTIVE_GIVE_UPS - 1):
            tap_gitlab.sync_full_refresh_stream(self.failing_stream, "tags", project)
        with self.assertRaises(tap_gitlab.RetriableAPIError):
            tap_gitlab.sync_full_refresh_stream(self.failing_stream, "tags", project)

    def test_successful_request_resets_the_streak(self):
        project = {"id": 2628}
        for _ in range(tap_gitlab.MAX_CONSECUTIVE_GIVE_UPS - 1):
            tap_gitlab.sync_full_refresh_stream(self.failing_stream, "tags", project)
        self.session.request.side_effect = [make_response(200)]
        tap_gitlab.request("https://gitlab.com/api/v4/projects/2628/labels")
        self.assertEqual(tap_gitlab.GIVE_UP_STREAK['count'], 0)
        tap_gitlab.sync_full_refresh_stream(self.failing_stream, "tags", project)
        self.assertEqual(tap_gitlab.GIVE_UP_STREAK['count'], 1)

    def test_connection_errors_are_skipped_like_5xx(self):
        def unreachable(project):
            raise requests.exceptions.ConnectionError("connection refused")
        tap_gitlab.sync_full_refresh_stream(unreachable, "tags", {"id": 1})
        self.assertEqual(tap_gitlab.GIVE_UP_STREAK['count'], 1)

    def test_successful_short_window_request_resets_the_streak(self):
        for _ in range(tap_gitlab.MAX_CONSECUTIVE_GIVE_UPS - 1):
            tap_gitlab.sync_full_refresh_stream(self.failing_stream, "members", {"id": 1})
        self.session.request.side_effect = [make_response(200)]
        tap_gitlab.request_few_tries(
            "https://gitlab.com/api/v4/projects/1/repository/commits",
            {"with_stats": "true"})
        self.assertEqual(tap_gitlab.GIVE_UP_STREAK['count'], 0)

    def test_other_exceptions_still_propagate(self):
        def broken(project):
            raise ValueError("boom")
        with self.assertRaises(ValueError):
            tap_gitlab.sync_full_refresh_stream(broken, "tags", {"id": 1})


if __name__ == "__main__":
    unittest.main()
