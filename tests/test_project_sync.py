import unittest
from unittest import mock

import tap_gitlab


class FakeAuth:
    def get_auth_token(self):
        return "token"


def make_response(status_code, content=b""):
    resp = mock.Mock()
    resp.status_code = status_code
    resp.content = content
    resp.headers = {}
    resp.json.return_value = []
    return resp


API = "https://gl.example.com/api/v4"
DELETED = "aerones-client-portal/uic-install-test-deletion_scheduled-731"
NOT_FOUND = b'{"message":"404 Project Not Found"}'


class ProjectNotFoundTests(unittest.TestCase):
    def setUp(self):
        self.auth_patch = mock.patch.object(tap_gitlab, "AUTH", FakeAuth())
        self.auth_patch.start()
        self.session_patch = mock.patch.object(tap_gitlab, "SESSION")
        self.session = self.session_patch.start()
        self.config_patch = mock.patch.dict(tap_gitlab.CONFIG, {"api_url": API})
        self.config_patch.start()

    def tearDown(self):
        self.config_patch.stop()
        self.session_patch.stop()
        self.auth_patch.stop()

    def test_404_on_project_detail_is_inaccessible_not_fatal(self):
        self.session.request.return_value = make_response(404, NOT_FOUND)
        with self.assertRaises(tap_gitlab.ResourceInaccessible):
            tap_gitlab.request(tap_gitlab.get_url(entity="projects", id=DELETED))
        self.assertEqual(self.session.request.call_count, 1)

    def test_404_on_group_detail_is_inaccessible_not_fatal(self):
        self.session.request.return_value = make_response(404, b'{"message":"404 Group Not Found"}')
        with self.assertRaises(tap_gitlab.ResourceInaccessible):
            tap_gitlab.request(tap_gitlab.get_url(entity="groups", id=106))

    def test_404_on_a_stream_endpoint_still_raises(self):
        self.session.request.return_value = make_response(404, NOT_FOUND)
        for entity in ("users", "merge_requests", "pipelines", "issues"):
            with self.assertRaises(Exception) as ctx:
                tap_gitlab.request(tap_gitlab.get_url(entity=entity, id=731, start_date="2026-01-01"))
            self.assertNotIsInstance(ctx.exception, tap_gitlab.ResourceInaccessible)

    def test_404_on_pipeline_detail_still_raises(self):
        self.session.request.return_value = make_response(404, NOT_FOUND)
        with self.assertRaises(Exception) as ctx:
            tap_gitlab.request(tap_gitlab.get_url(entity="pipelines_extended", id=731, secondary_id=9))
        self.assertNotIsInstance(ctx.exception, tap_gitlab.ResourceInaccessible)

    def test_deleted_project_is_skipped_and_sync_continues(self):
        self.session.request.return_value = make_response(404, NOT_FOUND)
        with mock.patch.object(tap_gitlab, "CATALOG") as catalog:
            self.assertIsNone(tap_gitlab.sync_project(DELETED))
            catalog.get_stream.assert_not_called()


class ProjectDedupTests(unittest.TestCase):
    def test_project_identifiers_cover_id_and_path(self):
        self.assertEqual(
            tap_gitlab.project_identifiers({"id": 731, "path_with_namespace": DELETED}),
            ["731", DELETED])
        self.assertEqual(tap_gitlab.project_identifiers({"id": 731}), ["731"])

    def test_config_projects_already_synced_via_group_are_not_synced_twice(self):
        config = {
            "groups": "5",
            "projects": "group/in-group 42 group/standalone",
        }
        with mock.patch.dict(tap_gitlab.CONFIG, config), \
                mock.patch.object(tap_gitlab, "CATALOG") as catalog, \
                mock.patch.object(tap_gitlab.singer, "write_state"), \
                mock.patch.object(tap_gitlab, "sync_group") as sync_group, \
                mock.patch.object(tap_gitlab, "sync_project") as sync_project:
            catalog.get_selected_streams.return_value = []
            sync_group.return_value = ["7", "group/in-group", "42", "group/other"]

            tap_gitlab.do_sync()

            sync_group.assert_called_once_with("5", ["group/in-group", "42", "group/standalone"])
            sync_project.assert_called_once_with("group/standalone")


if __name__ == "__main__":
    unittest.main()
