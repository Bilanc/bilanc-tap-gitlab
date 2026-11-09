import unittest
from unittest import mock

import tap_gitlab


API = "https://gl.example.com/api/v4"
SHA = "bafbfc17d27b2cfbfd209e42f813cdfdf8ae9eaa"

# One element of GET /projects/:id/merge_requests/:iid/commits.
API_COMMIT = {
    "id": SHA,
    "short_id": "bafbfc17",
    "created_at": "2026-11-09T15:05:25.000+01:00",
    "parent_ids": ["85816d3835d1ab0ddce36cf6e0530c74e6941077"],
    "title": "Fix the thing",
    "message": "Fix the thing\n\nWith a longer body.",
    "author_name": "Ada Example",
    "author_email": "ada@example.com",
    "authored_date": "2026-11-08T09:00:00.000+01:00",
    "committer_name": "Bo Example",
    "committer_email": "bo@example.com",
    "committed_date": "2026-11-09T15:05:25.000+01:00",
    "trailers": {},
    "extended_trailers": {},
    "web_url": "https://gl.example.com/group/project/-/commit/" + SHA,
}


class MergeRequestCommitsTests(unittest.TestCase):
    def setUp(self):
        self.config_patch = mock.patch.dict(
            tap_gitlab.CONFIG, {"api_url": API, "fetch_merge_request_commits": True})
        self.config_patch.start()
        self.catalog_patch = mock.patch.object(
            tap_gitlab, "CATALOG", tap_gitlab.do_discover(select_all=True))
        self.catalog_patch.start()

    def tearDown(self):
        self.catalog_patch.stop()
        self.config_patch.stop()

    def sync(self, rows):
        with mock.patch.object(tap_gitlab, "gen_request", return_value=iter(rows)) as gen_request, \
                mock.patch.object(tap_gitlab.singer, "write_record") as write_record:
            tap_gitlab.sync_merge_request_commits({"id": 42}, {"iid": 7})
        gen_request.assert_called_once_with(API + "/projects/42/merge_requests/7/commits")
        return [call.args[1] for call in write_record.call_args_list]

    def test_record_carries_the_commit_metadata(self):
        (record,) = self.sync([dict(API_COMMIT)])

        self.assertEqual(record["project_id"], 42)
        self.assertEqual(record["merge_request_iid"], 7)
        self.assertEqual(record["commit_id"], SHA)
        self.assertEqual(record["commit_short_id"], "bafbfc17")
        self.assertEqual(record["web_url"], API_COMMIT["web_url"])
        self.assertEqual(record["author_name"], "Ada Example")
        self.assertEqual(record["author_email"], "ada@example.com")
        self.assertEqual(record["committer_name"], "Bo Example")
        self.assertEqual(record["committer_email"], "bo@example.com")
        self.assertEqual(record["message"], "Fix the thing\n\nWith a longer body.")

    def test_commit_dates_are_normalised_to_utc(self):
        (record,) = self.sync([dict(API_COMMIT)])

        self.assertEqual(record["authored_date"], "2026-11-08T08:00:00.000000Z")
        self.assertEqual(record["committed_date"], "2026-11-09T14:05:25.000000Z")

    def test_fields_outside_the_schema_are_dropped(self):
        (record,) = self.sync([dict(API_COMMIT)])

        for field in ("id", "short_id", "title", "created_at", "parent_ids", "trailers"):
            self.assertNotIn(field, record)

    def test_commit_without_metadata_is_still_written(self):
        bare = {"id": SHA, "short_id": "bafbfc17", "author_email": None, "committed_date": None}
        (record,) = self.sync([bare])

        self.assertEqual(record["commit_id"], SHA)
        self.assertIsNone(record["author_email"])
        self.assertIsNone(record["committed_date"])
        self.assertNotIn("author_name", record)

    def test_stream_schema_and_key_are_what_the_target_sees(self):
        stream = tap_gitlab.CATALOG.get_stream("merge_request_commits")

        self.assertTrue(stream.is_selected())
        self.assertEqual(stream.key_properties, ["project_id", "merge_request_iid", "commit_id"])
        properties = stream.schema.to_dict()["properties"]
        for field in ("author_name", "author_email", "authored_date",
                      "committer_name", "committer_email", "committed_date", "message"):
            self.assertIn(field, properties)


if __name__ == "__main__":
    unittest.main()
