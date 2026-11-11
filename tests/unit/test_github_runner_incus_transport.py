"""Exercise the actual server-side identity entry without credentials or HTTP.

The fake reader is a daemon-owned dependency, not caller-supplied native facts.
These tests establish no live token, API latency, issuer or Incus authority.
"""
import copy
import inspect
import json
import ssl
import unittest
from unittest import mock
import urllib.error

import test_github_runner_incus_identity as fixtures


identity = fixtures.identity
PREFIX = "https://api.github.com/repos/" + fixtures.REPOSITORY
RUN_URL = PREFIX + "/actions/runs/501"
PAGE_URL = RUN_URL + "/attempts/1/jobs?per_page=100&page="
JOB_URL = PREFIX + "/actions/jobs/902"
BRANCH_URL = PREFIX + "/branches/main"
FAKE_ACCESS_TOKEN = "synthetic-transport-only-token"


class ScriptedReader:
    """Accept only the expected fixed sequence, including bearer placement."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def read(self, url, *, bearer=None):
        self.calls.append((url, bearer))
        if not self.replies:
            raise AssertionError("unexpected read")
        wanted_url, payload = self.replies.pop(0)
        if url != wanted_url:
            raise AssertionError("wrong fixed route")
        wanted_bearer = None if url == identity.JWKS_URL else FAKE_ACCESS_TOKEN
        if bearer != wanted_bearer:
            raise AssertionError("credential crossed origin boundary")
        return payload if isinstance(payload, bytes) else fixtures.json_bytes(payload)


class GithubAssignmentTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.CurrentJobIdentityTests.setUpClass()

    def setUp(self):
        self.fixture = fixtures.CurrentJobIdentityTests()
        self.fixture.setUp()
        self.branch = {"protected": True, "commit": {"sha": fixtures.CALLER_SHA}}

    def replies(self, *, pages=None, current_job=None, current_run=None, branch=None):
        f = self.fixture
        if pages is None:
            pages = [{"total_count": 2, "jobs": f.jobs["jobs"]}]
        return [
            (identity.JWKS_URL, f.jwks), (RUN_URL, f.run),
            *[(PAGE_URL + str(i), page) for i, page in enumerate(pages, 1)],
            (JOB_URL, f.job if current_job is None else current_job),
            (RUN_URL, f.run if current_run is None else current_run),
            (BRANCH_URL, self.branch if branch is None else branch),
        ]

    def test_validation_main_dispatch_uses_actual_root_entry_and_repeated_native_readback(self):
        self.fixture.receiver_fixture()
        prefix = "https://api.github.com/repos/" + self.fixture.policy.repository
        replies = [(url.replace(PREFIX, prefix), payload) for url, payload in self.replies()]
        reader = ScriptedReader(replies)
        result = self.verify(reader)
        self.assertEqual((result.job_id, result.runner_id, result.service_uid), (902, 61, 2101))
        self.assertEqual(reader.replies, [])
        self.assertEqual(len(reader.calls), 6)
        self.assertTrue(all(url.startswith(prefix + "/") for url, _ in reader.calls[1:]))

    def verify(self, reader, *, token=None, clock=None):
        return identity.verify_github_assignment(
            self.fixture.token() if token is None else token, self.fixture.policy,
            audience=fixtures.AUDIENCE, peer_uid=2101,
            access_token=FAKE_ACCESS_TOKEN, reader=reader,
            clock=(lambda: fixtures.NOW) if clock is None else clock,
        )

    def test_actual_entry_acquires_and_refreshes_fixed_assignment_routes(self):
        reader = ScriptedReader(self.replies())
        result = self.verify(reader)
        self.assertEqual((result.run_id, result.check_run_id, result.job_id), (501, 731, 902))
        self.assertFalse(reader.replies)
        self.assertEqual(reader.calls[0], (identity.JWKS_URL, None))
        self.assertEqual([url for url, _ in reader.calls],
                         [identity.JWKS_URL, RUN_URL, PAGE_URL + "1", JOB_URL, RUN_URL, BRANCH_URL])
        self.assertTrue(all(bearer == FAKE_ACCESS_TOKEN for _, bearer in reader.calls[1:]))

    def paginated_rows(self):
        rows = []
        for index in range(100):
            rows.append({**self.fixture.job, "id": 1000 + index,
                         "check_run_url": PREFIX + "/check-runs/" + str(2000 + index)})
        return rows

    def test_complete_multiple_pages_join_check_id_not_job_name_or_job_id(self):
        rows = self.paginated_rows()
        pages = [{"total_count": 101, "jobs": rows},
                 {"total_count": 101, "jobs": [self.fixture.job]}]
        reader = ScriptedReader(self.replies(pages=pages))
        result = self.verify(reader)
        self.assertEqual(result.job_id, 902)
        self.assertEqual(result.check_run_id, 731)
        self.assertFalse(reader.replies)
        self.assertIn((PAGE_URL + "2", FAKE_ACCESS_TOKEN), reader.calls)

    def test_duplicate_or_changed_total_pages_fail_before_refresh(self):
        rows = self.paginated_rows()
        duplicate = copy.deepcopy(rows[0])
        cases = (
            [{"total_count": 101, "jobs": rows}, {"total_count": 101, "jobs": [duplicate]}],
            [{"total_count": 101, "jobs": rows}, {"total_count": 102, "jobs": [self.fixture.job]}],
            [{"total_count": 101, "jobs": [self.fixture.job]}],
            [{"total_count": True, "jobs": [self.fixture.job]}],
        )
        for pages in cases:
            with self.subTest(page_count=len(pages)):
                reader = ScriptedReader(self.replies(pages=pages))
                with self.assertRaises(identity.Denied):
                    self.verify(reader)
                self.assertNotIn((JOB_URL, FAKE_ACCESS_TOKEN), reader.calls)

    def test_final_job_cancel_reassign_or_identity_swap_denies(self):
        changes = (
            {"status": "completed", "conclusion": "cancelled"},
            {"runner_id": 62, "runner_name": "another-listener"},
            {"run_id": 502}, {"head_sha": "c" * 40}, {"id": 909},
        )
        for change in changes:
            with self.subTest(change=change):
                reader = ScriptedReader(self.replies(current_job={**self.fixture.job, **change}))
                with self.assertRaises(identity.Denied):
                    self.verify(reader)

    def test_root_cell_name_is_rechecked_on_actual_joined_job_readback(self):
        from dataclasses import replace
        name = "synthetic-heavy / profile-cells (keycloak-vm)"
        self.fixture.policy = replace(self.fixture.policy, required_native_job_name=name)
        self.fixture.job["name"] = name
        self.assertEqual(self.verify(ScriptedReader(self.replies())).job_id, 902)
        for change in ({"name": "other-cell"}, {"name": None}, {"name": name + " "}):
            with self.subTest(change=change):
                reader = ScriptedReader(self.replies(current_job={**self.fixture.job, **change}))
                with self.assertRaisesRegex(identity.Denied, "native-job-cell-name"):
                    self.verify(reader)

    def test_final_run_cancel_new_attempt_or_reusable_drift_denies(self):
        changes = (
            {"status": "completed", "conclusion": "cancelled"}, {"run_attempt": 2},
            {"head_sha": "c" * 40}, {"referenced_workflows": []},
        )
        for change in changes:
            with self.subTest(change=change):
                reader = ScriptedReader(self.replies(current_run={**self.fixture.run, **change}))
                with self.assertRaises(identity.Denied):
                    self.verify(reader)

    def test_current_main_must_still_be_exact_and_protected(self):
        for branch in ({"protected": False, "commit": {"sha": fixtures.CALLER_SHA}},
                       {"protected": "true", "commit": {"sha": fixtures.CALLER_SHA}},
                       {"protected": True, "commit": {"sha": "c" * 40}}):
            with self.subTest(branch=branch):
                reader = ScriptedReader(self.replies(branch=branch))
                with self.assertRaises(identity.Denied):
                    self.verify(reader)

    def test_token_expiry_and_snapshot_age_are_rechecked_after_reads(self):
        for final_time in (fixtures.NOW + 11, self.fixture.claims["exp"]):
            times = iter((fixtures.NOW, fixtures.NOW, fixtures.NOW, final_time))
            with self.subTest(final_time=final_time):
                reader = ScriptedReader(self.replies())
                with self.assertRaises(identity.Denied):
                    self.verify(reader, clock=lambda: next(times))

    def test_untrusted_jku_header_never_selects_a_reader_destination(self):
        token = self.fixture.token(header={"alg": "RS256", "kid": "synthetic-rsa-key",
                                           "jku": "https://attacker.example.invalid/jwks"})
        reader = ScriptedReader([(identity.JWKS_URL, self.fixture.jwks)])
        with self.assertRaises(identity.Denied):
            self.verify(reader, token=token)
        self.assertEqual(reader.calls, [(identity.JWKS_URL, None)])

    def test_public_entry_has_no_caller_run_jobs_or_jwks_snapshot_parameters(self):
        parameters = inspect.signature(identity.verify_github_assignment).parameters
        self.assertFalse({"run", "jobs", "jwks_json", "observed_at"} & parameters.keys())
        reader = ScriptedReader([])
        with self.assertRaises(TypeError):
            identity.verify_github_assignment(
                self.fixture.token(), self.fixture.policy, audience=fixtures.AUDIENCE,
                peer_uid=2101, access_token=FAKE_ACCESS_TOKEN, reader=reader,
                run=self.fixture.run, jobs=self.fixture.jobs,
            )
        self.assertEqual(reader.calls, [])


class HTTPSReaderBoundaryTests(unittest.TestCase):
    def test_foreign_origin_or_credential_on_jwks_denies_before_transport(self):
        cases = (
            ("http://api.github.com/repos/ltn-it/example", None),
            ("https://api.github.com.attacker.invalid/repos/ltn-it/example", None),
            ("https://user@api.github.com/repos/ltn-it/example", None),
            ("https://attacker.invalid/.well-known/jwks", None),
            (identity.JWKS_URL + "?alternate=1", None),
            (identity.JWKS_URL, FAKE_ACCESS_TOKEN),
            (RUN_URL, "bad\ncredential"),
        )
        for url, bearer in cases:
            with self.subTest(url_kind=url.split(":", 1)[0]):
                with mock.patch.object(identity.urllib.request, "build_opener") as build:
                    with self.assertRaises(identity.Denied):
                        identity.HTTPSReader().read(url, bearer=bearer)
                    build.assert_not_called()

    def test_https_verified_fixed_get_and_bearer_placement(self):
        for url, bearer in ((identity.JWKS_URL, None), (RUN_URL, FAKE_ACCESS_TOKEN)):
            with self.subTest(origin=url.split("/", 3)[2]):
                response = mock.MagicMock()
                response.status = 200
                response.read.return_value = b"{}"
                opener = mock.MagicMock()
                opener.open.return_value.__enter__.return_value = response
                opener.open.return_value.__exit__.return_value = False
                with mock.patch.object(identity.urllib.request, "build_opener", return_value=opener) as build:
                    self.assertEqual(identity.HTTPSReader().read(url, bearer=bearer), b"{}")
                request = opener.open.call_args.args[0]
                self.assertEqual(request.full_url, url)
                self.assertEqual(request.get_method(), "GET")
                self.assertEqual(opener.open.call_args.kwargs, {"timeout": 10})
                self.assertEqual(request.get_header("Authorization"),
                                 None if bearer is None else "Bearer " + FAKE_ACCESS_TOKEN)
                handlers = build.call_args.args
                self.assertTrue(any(isinstance(handler, identity.NoRedirect) for handler in handlers))
                https = next(h for h in handlers if isinstance(h, identity.urllib.request.HTTPSHandler))
                self.assertTrue(https._context.check_hostname)
                self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(any(isinstance(h, identity.urllib.request.ProxyHandler)
                                    and h.proxies == {} for h in handlers))

    def test_redirect_is_an_explicit_denial_not_another_read(self):
        with self.assertRaises(identity.Denied) as error:
            identity.NoRedirect().redirect_request(None, None, 302, "found", {},
                                                   "https://attacker.invalid/collect")
        self.assertEqual(str(error.exception), "https-redirect-denied")

    def test_transport_failure_does_not_retry_or_echo_response_location(self):
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.URLError("sensitive-url-and-body-sentinel")
        with mock.patch.object(identity.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(identity.Denied) as error:
                identity.HTTPSReader().read(RUN_URL, bearer=FAKE_ACCESS_TOKEN)
        self.assertEqual(str(error.exception), "https-read-failed")
        opener.open.assert_called_once()

    def test_status_and_body_limits_deny_without_retry(self):
        for status, body in ((503, b"private-error-body"), (200, b"x" * 8388609)):
            with self.subTest(status=status):
                response = mock.MagicMock()
                response.status = status
                response.read.return_value = body
                opener = mock.MagicMock()
                opener.open.return_value.__enter__.return_value = response
                opener.open.return_value.__exit__.return_value = False
                with mock.patch.object(identity.urllib.request, "build_opener", return_value=opener):
                    with self.assertRaises(identity.Denied):
                        identity.HTTPSReader().read(RUN_URL, bearer=FAKE_ACCESS_TOKEN)
                opener.open.assert_called_once()
                if status == 200:
                    response.read.assert_called_once_with(8388609)
                else:
                    response.read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
