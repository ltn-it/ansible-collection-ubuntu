"""Exercise the actual server-side identity entry without credentials or HTTP.

The fake reader is a daemon-owned dependency, not caller-supplied native facts.
These tests establish no live token, API latency, issuer or Incus authority.
"""
import copy
import http.client
import inspect
import ssl
import threading
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
    """Fixed phases; only independent requests within one phase may reorder."""
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []
        self.lock = threading.Lock()
        self.phases = [list(self.replies[:1]), list(self.replies[1:3])]
        self.phases.extend([[row] for row in self.replies[3:-3]])
        self.phases.extend((list(self.replies[-3:-1]), list(self.replies[-1:])))

    def read(self, url, *, bearer=None):
        with self.lock:
            self.calls.append((url, bearer))
            while self.phases and not self.phases[0]:
                self.phases.pop(0)
            if not self.phases:
                raise AssertionError("unexpected read")
            matches = [row for row in self.phases[0] if row[0] == url]
            if len(matches) != 1:
                raise AssertionError("wrong fixed route phase")
            row = matches[0]
            self.phases[0].remove(row)
            self.replies.remove(row)
            payload = row[1]
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
        self.assertEqual([url for url, _ in reader.calls[:1]], [identity.JWKS_URL])
        self.assertCountEqual([url for url, _ in reader.calls[1:3]], [RUN_URL, PAGE_URL + "1"])
        self.assertCountEqual([url for url, _ in reader.calls[3:]], [JOB_URL, RUN_URL, BRANCH_URL])
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

    def test_history_retries_one_identical_get_and_shares_the_budget(self):
        budget = threading.BoundedSemaphore()
        reader = identity.HTTPSReader(claim_transport_retry=lambda: budget.acquire(blocking=False))
        opener = mock.MagicMock()
        response = mock.MagicMock(status=200)
        response.read.return_value = b"{}"
        handle = mock.MagicMock()
        handle.__enter__.return_value = response
        opener.open.side_effect = [
            urllib.error.URLError(http.client.RemoteDisconnected()),
            handle,
            TimeoutError(),
        ]
        with mock.patch.object(identity.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(reader.read(RUN_URL, bearer=FAKE_ACCESS_TOKEN), b"{}")
            with self.assertRaisesRegex(identity.Denied, "^https-read-failed$"):
                reader.read(JOB_URL, bearer=FAKE_ACCESS_TOKEN)
        self.assertEqual(opener.open.call_count, 3)
        first, retry, later = [call.args[0] for call in opener.open.call_args_list]
        self.assertIs(first, retry)
        self.assertEqual((first.full_url, first.get_method(), later.full_url), (RUN_URL, "GET", JOB_URL))

    def test_history_fails_closed_on_permission_tls_and_repeated_transport_errors(self):
        cases = (
            (urllib.error.HTTPError(RUN_URL, 403, "private-sentinel", {}, None), "https-status", 1),
            (urllib.error.URLError(ssl.SSLCertVerificationError("private-sentinel")), "https-read-failed", 1),
            (ConnectionResetError("private-sentinel"), "https-read-failed", 2),
        )
        for failure, code, calls in cases:
            with self.subTest(kind=type(failure).__name__):
                opener = mock.Mock()
                opener.open.side_effect = failure
                claim = mock.Mock(return_value=True)
                reader = identity.HTTPSReader(claim_transport_retry=claim)
                with mock.patch.object(identity.urllib.request, "build_opener", return_value=opener):
                    with self.assertRaisesRegex(identity.Denied, f"^{code}$"):
                        reader.read(RUN_URL, bearer=FAKE_ACCESS_TOKEN)
                self.assertEqual(opener.open.call_count, calls)
                self.assertEqual(claim.call_count, calls - 1)

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


class JoinedNativeIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.CurrentJobIdentityTests.setUpClass()

    def setUp(self):
        self.subject = GithubAssignmentTransportTests()
        self.subject.setUp()

    def reader(self, fail=False):
        class JoinedReader(ScriptedReader):
            def __init__(inner):
                super().__init__(self.subject.replies())
                inner.pre = threading.Barrier(2, timeout=2)
                inner.post = threading.Barrier(2, timeout=2)
                inner.count_lock = threading.Lock()
                inner.run_reads = inner.active = inner.maximum = 0
                inner.finished = []
            def read(inner, url, *, bearer=None):
                if url == identity.JWKS_URL:
                    return super().read(url, bearer=bearer)
                with inner.count_lock:
                    if url == RUN_URL:
                        inner.run_reads += 1
                    first_run = url == RUN_URL and inner.run_reads == 1
                    group = inner.pre if first_run or url == PAGE_URL + '1' else inner.post
                    inner.active += 1
                    inner.maximum = max(inner.maximum, inner.active)
                try:
                    if url != BRANCH_URL:
                        group.wait()
                    if fail and url == BRANCH_URL:
                        raise ValueError('modeled-readback-failure')
                    return super().read(url, bearer=bearer)
                finally:
                    with inner.count_lock:
                        inner.active -= 1
                        inner.finished.append(url)
        return JoinedReader()

    def test_two_independent_pairs_join_before_final_branch_read(self):
        reader = self.reader()
        result = self.subject.verify(reader)
        self.assertEqual(result.job_id, 902)
        self.assertEqual(reader.maximum, 2)
        self.assertEqual(reader.finished[-1], BRANCH_URL)
        self.assertEqual(reader.active, 0)
        self.assertEqual(len(reader.finished), 5)
        self.assertFalse(reader.replies)

    def test_workflow_read_starts_only_after_initial_assignment_is_valid(self):
        subject = self.subject
        jobs = [{"total_count": 0, "jobs": []}]
        reader = ScriptedReader(subject.replies(pages=jobs))
        with self.assertRaises(identity.Denied):
            identity.verify_github_workflow_assignment(subject.fixture.token(), subject.fixture.policy,
                audience=fixtures.AUDIENCE, peer_uid=2101, access_token=FAKE_ACCESS_TOKEN,
                reader=reader, clock=lambda: fixtures.NOW)
        self.assertCountEqual([url for url, _ in reader.calls], [identity.JWKS_URL, RUN_URL, PAGE_URL + "1"])

    def test_only_commit_workflow_overlaps_validated_assignment_refresh(self):
        workflow_url = PREFIX + "/contents/.github/workflows/collection-ci.yml?ref=" + fixtures.CALLER_SHA
        for accepted in (True, False):
            with self.subTest(accepted=accepted):
                rendezvous = threading.Barrier(2, timeout=5)
                finished = threading.Event()
                class Reader(ScriptedReader):
                    def read(inner, url, *, bearer=None):
                        if url == workflow_url:
                            rendezvous.wait()
                            finished.set()
                            return b'{"type":"file"}'
                        if url == JOB_URL:
                            rendezvous.wait()
                        return super().read(url, bearer=bearer)
                reader = Reader(self.subject.replies(branch={"protected": accepted, "commit": {"sha": fixtures.CALLER_SHA}}))
                def verify():
                    return identity.verify_github_workflow_assignment(
                        self.subject.fixture.token(), self.subject.fixture.policy, audience=fixtures.AUDIENCE,
                        peer_uid=2101, access_token=FAKE_ACCESS_TOKEN, reader=reader, clock=lambda: fixtures.NOW)
                if accepted:
                    who, workflow = verify()
                    self.assertEqual((who.job_id, workflow), (902, {"type": "file"}))
                else:
                    with self.assertRaisesRegex(identity.Denied, "current-protected-main"):
                        verify()
                self.assertTrue(finished.is_set())
                self.assertFalse(reader.replies)
                self.assertEqual(reader.calls[-1][0], BRANCH_URL)

    def test_failed_branch_waits_for_workflow_and_keeps_its_error(self):
        from concurrent.futures import ThreadPoolExecutor
        from unittest.mock import patch
        workflow_started, branch_denied, release = (threading.Event() for _ in range(3))
        require = identity.require

        def observe_denial(condition, reason):
            if not condition and reason == "current-protected-main":
                branch_denied.set()
            return require(condition, reason)

        class Reader(ScriptedReader):
            def read(inner, url, *, bearer=None):
                if "/contents/" in url:
                    workflow_started.set()
                    release.wait(timeout=5)
                    raise ValueError("workflow-read-failed")
                return super().read(url, bearer=bearer)

        reader = Reader(self.subject.replies(branch={"protected": False}))
        with patch.object(identity, "require", side_effect=observe_denial), ThreadPoolExecutor(max_workers=1) as pool:
            verification = pool.submit(identity.verify_github_workflow_assignment,
                self.subject.fixture.token(), self.subject.fixture.policy, audience=fixtures.AUDIENCE,
                peer_uid=2101, access_token=FAKE_ACCESS_TOKEN, reader=reader, clock=lambda: fixtures.NOW)
            try:
                self.assertTrue(workflow_started.wait(timeout=3))
                self.assertTrue(branch_denied.wait(timeout=3))
                self.assertFalse(verification.done())
            finally:
                release.set()
            with self.assertRaisesRegex(identity.Denied, "current-protected-main"):
                verification.result(timeout=3)

    def test_tip_advance_during_final_job_read_is_observed(self):
        subject = self.subject
        class AdvancingReader(ScriptedReader):
            def read(inner, url, *, bearer=None):
                response = super().read(url, bearer=bearer)
                if url == JOB_URL:
                    subject.branch["commit"]["sha"] = "f" * 40
                return response
        with self.assertRaisesRegex(identity.Denied, "current-protected-main"):
            subject.verify(AdvancingReader(subject.replies()))

    def test_read_failure_joins_all_other_readbacks_without_a_proof(self):
        reader = self.reader(fail=True)
        with self.assertRaisesRegex(ValueError, 'modeled-readback-failure'):
            self.subject.verify(reader)
        self.assertEqual(reader.active, 0)
        self.assertEqual(len(reader.finished), 5)
