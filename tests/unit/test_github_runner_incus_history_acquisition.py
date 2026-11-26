"""Complete bounded historical reads, failure joining, and native effect barriers."""
import base64
import collections
import copy
import hashlib
import importlib
import pathlib
import socket
import sys
import threading
import time
import unittest
from contextlib import ExitStack
from types import SimpleNamespace as NS
from unittest.mock import patch

FILES = pathlib.Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import run_factory as f, operating_cells as cells, ledger
from incus_lease_issuer.identity import Denied

NAMES = ["origin", "prior", "third", "fourth", "fifth", "sixth", "seventh"]
ATTRS = ["_continuation_original_native", "_continuation_original_native",
         "_continuation_third_native", "_continuation_fourth_native",
         "_continuation_fifth_native", "_continuation_sixth_native",
         "_continuation_seventh_native"]

def inputs():
    fixtures = [('continuation', 'original_native'), ('two_history_continuation', 'prior_native'), ('three_history_continuation', 'third_native'), ('four_history_continuation', 'fourth_native'), ('fifth_partial_continuation', 'fifth_native'), ('sixth_partial_continuation', 'sixth_native'), ('seventh_prelease_continuation', 'native')]
    args = [getattr(importlib.import_module('test_github_runner_incus_operating_' + module), fun)() for module, fun in fixtures]
    funcs = [cells.origin_native_projection, cells.prior_native_projection, cells.third_native_projection, cells.fourth_native_projection, cells.fifth_native_projection, cells.sixth_native_projection, cells.seventh_native_projection]
    projections = [fun(*values) for fun, values in zip(funcs, args)]
    responses = {}
    sequences = {}
    for index, values in enumerate(args):
        run, inventory, checks, *commit = values
        runid = run['id']
        prefix = '/actions/runs/' + str(runid)
        responses[prefix] = run
        path = prefix + '/attempts/1/jobs?per_page=100&page=1'
        if index < 4:
            responses[path] = {'total_count': 24, 'jobs': inventory['jobs'][:12]}
            responses[path[:-1] + '2'] = {'total_count': 24, 'jobs': inventory['jobs'][12:]}
        else:
            responses[path] = inventory
        for check in checks:
            responses['/check-runs/' + str(check['id'])] = check
        if commit:
            responses['/git/commits/' + run['head_sha']] = commit[0]
    legacy = {'native_origin': projections[0]}
    two = {'legacy_qualification': legacy, 'native_prior': projections[1]}
    three = {'previous_qualification': two, 'native_third': projections[2]}
    four = {'previous_qualification': three, 'native_fourth': projections[3]}
    five = {'previous_qualification': four, 'native_fifth': projections[4]}
    six = {'previous_qualification': five, 'native_sixth': projections[5]}
    seven = {'previous_qualification': six, 'native_seventh': projections[6]}
    return ({'schema': 7}, seven, responses, args, projections)

class HistoryAcquisitionTests(unittest.TestCase):

    def setUp(self):
        self.descriptor, self.receipt, self.responses, self.args, self.projections = inputs()

    def get(self, path):
        return copy.deepcopy(self.responses[path])

    def wrapped(self, stack, *, fail=None, barrier=False):
        lock = threading.Lock()
        state = {'active': 0, 'maximum': 0, 'started': [], 'finished': [], 'threads': set()}
        gate = threading.Barrier(4) if barrier else None
        originals = {n: getattr(f, n) for n in set(ATTRS)}

        def make(attr):

            def run(get, **kw):
                label = 'prior' if attr == ATTRS[0] and kw.get('prior') else NAMES[ATTRS.index(attr)]
                with lock:
                    state['active'] += 1
                    state['maximum'] = max(state['maximum'], state['active'])
                    state['started'].append(label)
                    state['threads'].add(threading.get_ident())
                try:
                    if gate and NAMES.index(label) < 4:
                        gate.wait(timeout=5)
                    time.sleep(0.004 * (7 - NAMES.index(label)))
                    if fail == label:
                        raise Denied('modeled-family-' + label)
                    return originals[attr](get, **kw)
                finally:
                    with lock:
                        state['active'] -= 1
                        state['finished'].append(label)
            return run
        for attr in set(ATTRS):
            stack.enter_context(patch.object(f, attr, make(attr)))
        return state

    def test_real_four_worker_overlap_same_complete_queries_and_pagination(self):
        expected = []
        for i, attr in enumerate(ATTRS):

            def get(path):
                expected.append((NAMES[i], path))
                return self.get(path)
            getattr(f, attr)(get, **{'prior': True} if i == 1 else {})
        actual = []
        lock = threading.Lock()

        def get(path):
            with lock:
                actual.append(path)
            return self.get(path)
        with ExitStack() as stack:
            state = self.wrapped(stack, barrier=True)
            f._continuation_native_histories(get, self.descriptor, self.receipt)
        self.assertEqual(state['maximum'], 4)
        self.assertEqual(len(state['threads']), 4)
        self.assertEqual(state['active'], 0)
        self.assertCountEqual(state['finished'], NAMES)
        self.assertEqual(collections.Counter(actual), collections.Counter((path for label, path in expected)))
        for label in NAMES:
            paths = [p for name, p in expected if name == label]
            self.assertEqual([p for p in actual if p in set(paths)], paths)

    def test_every_projection_drift_denied_and_all_workers_joined(self):

        def receipts():
            seven = copy.deepcopy(self.receipt)
            six = seven['previous_qualification']
            five = six['previous_qualification']
            four = five['previous_qualification']
            three = four['previous_qualification']
            two = three['previous_qualification']
            legacy = two['legacy_qualification']
            return (seven, [legacy, two, three, four, five, six, seven])
        for index, label in enumerate(NAMES):
            receipt, rows = receipts()
            rows[index]['native_' + ('origin' if index == 0 else label)] = {'wrong': True}
            with self.subTest(label=label), ExitStack() as stack:
                state = self.wrapped(stack, barrier=True)
                with self.assertRaisesRegex(Denied, 'continuation-' + ('original' if index == 0 else label) + '-native-drift'):
                    f._continuation_native_histories(self.get, self.descriptor, receipt)
                self.assertEqual(state['active'], 0)
                self.assertCountEqual(state['finished'], NAMES)

    def test_every_helper_exception_is_joined_before_escape(self):
        for label in NAMES:
            with self.subTest(label=label), ExitStack() as stack:
                state = self.wrapped(stack, fail=label, barrier=True)
                with self.assertRaisesRegex(Denied, 'modeled-family-' + label):
                    f._continuation_native_histories(self.get, self.descriptor, self.receipt)
                self.assertEqual(state['active'], 0)
                self.assertCountEqual(state['finished'], NAMES)

    def test_declaration_failure_priority_over_finish_order(self):
        receipt = copy.deepcopy(self.receipt)
        row = receipt['previous_qualification']['previous_qualification']['previous_qualification']['previous_qualification']['previous_qualification']['legacy_qualification']
        row['native_origin'] = {'drift': True}
        with ExitStack() as stack:
            state = self.wrapped(stack, fail='seventh', barrier=True)
            with self.assertRaisesRegex(Denied, 'continuation-original-native-drift'):
                f._continuation_native_histories(self.get, self.descriptor, receipt)
            self.assertEqual(state['active'], 0)
            self.assertCountEqual(state['finished'], NAMES)

    def test_submit_failure_and_baseexceptions_join_started_workers(self):
        real = f.ThreadPoolExecutor

        class SubmissionFailure:

            def __init__(self, **kw):
                self.pool = real(**kw)
                self.count = 0

            def __enter__(self):
                self.pool.__enter__()
                return self

            def __exit__(self, *exc):
                return self.pool.__exit__(*exc)

            def submit(self, *args, **kwargs):
                self.count += 1
                if self.count == 3:
                    raise RuntimeError('modeled-third-submit-failure')
                return self.pool.submit(*args, **kwargs)
        with ExitStack() as stack:
            state = self.wrapped(stack)
            stack.enter_context(patch.object(f, 'ThreadPoolExecutor', SubmissionFailure))
            with self.assertRaisesRegex(RuntimeError, 'third-submit'):
                f._continuation_native_histories(self.get, self.descriptor, self.receipt)
            self.assertEqual(state['active'], 0)
            self.assertCountEqual(state['finished'], ['origin', 'prior'])
        for kind in [RuntimeError, SystemExit]:
            finished = threading.Event()
            original = f._continuation_seventh_native

            def fail(get):
                try:
                    raise kind('modeled-base-or-runtime-failure')
                finally:
                    finished.set()
            before_threads = {t.ident for t in threading.enumerate()}
            with self.subTest(kind=kind), patch.object(f, '_continuation_seventh_native', fail):
                with self.assertRaises(kind):
                    f._continuation_native_histories(self.get, self.descriptor, self.receipt)
                self.assertTrue(finished.is_set())
                self.assertEqual({t.ident for t in threading.enumerate()}, before_threads)

    def test_missing_inputs_and_all_schemas_fail_closed_or_keep_exact_family_count(self):
        rows = []
        row = self.receipt
        for i in range(7, 1, -1):
            rows.append((i, row))
            row = row['previous_qualification'] if i != 2 else row['legacy_qualification']
        rows.append((1, row))
        for schema, receipt in rows:
            with self.subTest(schema=schema):
                f._continuation_native_histories(self.get, {'schema': schema}, receipt)
        broken = copy.deepcopy(self.receipt)
        broken.pop('native_seventh')
        with self.assertRaises(KeyError):
            f._continuation_native_histories(self.get, self.descriptor, broken)

    def test_twenty_fourth_and_fifth_require_every_native_family_and_reject_projection_drift(self):
        phases = ("eighth", "ninth", "tenth", "eleventh", "twelfth", "thirteenth", "fourteenth",
                  "fifteenth", "sixteenth", "seventeenth", "eighteenth", "nineteenth", "twentieth",
                  "twenty_first", "twenty_second", "twenty_third", "twenty_fourth")
        with self.subTest(schema=24):
            self.assert_continuation_native_family_drift_rejected(24, phases)
        with self.subTest(schema=25):
            self.assert_continuation_native_family_drift_rejected(25, (*phases, "twenty_fifth"))

    def assert_continuation_native_family_drift_rejected(self, schema, phases):
        receipt = self.receipt
        with ExitStack() as stack:
            legacy = self.wrapped(stack)
            checks = {}
            for phase in phases:
                graph = {"fixture": phase}
                receipt = {"previous_qualification": receipt, f"native_{phase}": graph}
                checks[phase] = stack.enter_context(patch.object(f, f"_continuation_{phase}_native", return_value=graph))
            f._continuation_native_histories(self.get, {"schema": schema}, receipt)
            self.assertCountEqual(legacy["finished"], NAMES)
            for check in checks.values():
                check.assert_called_once_with(self.get)
            for depth, phase in enumerate(reversed(phases[-3:])):
                broken = copy.deepcopy(receipt)
                family = broken
                for _ in range(depth):
                    family = family["previous_qualification"]
                family[f"native_{phase}"] = {"fixture": "different"}
                reason = f"continuation-{phase.replace('_', '-')}-native-drift"
                with self.subTest(phase=phase), self.assertRaisesRegex(Denied, reason):
                    f._continuation_native_histories(self.get, {"schema": schema}, broken)

    def test_twenty_fourth_provider_readback_rejects_inventory_drift(self):
        original = {"total_count": 24, "jobs": [{"id": 7}]}
        changed = {"total_count": 24, "jobs": [{"id": 8}]}
        run = {"id": cells.TWENTY_FOURTH_RUN}
        checks = [{"id": value} for value in cells.TWENTY_FOURTH_CHECKS]
        prefix = f"/actions/runs/{cells.TWENTY_FOURTH_RUN}"
        jobs = prefix + "/attempts/1/jobs?per_page=100&page=1"
        responses = {prefix: run, **{f"/check-runs/{row['id']}": row for row in checks}}
        inventories = iter((original, changed))

        def get(path):
            return next(inventories) if path == jobs else responses[path]

        with patch.object(cells, "twenty_fourth_native_projection", return_value={"fixture": "exact"}) as project:
            with self.assertRaises(Denied):
                f._continuation_twenty_fourth_native(get)
        project.assert_called_once_with(run, original, checks)

    def test_data_missing_pagination_and_second_readback_still_deny(self):
        origin = '/actions/runs/' + str(self.args[0][0]['id']) + '/attempts/1/jobs?per_page=100&page='
        for mode in ['incomplete', 'bad-count', 'missing', 'second-readback']:
            count = collections.Counter()

            def get(path):
                count[path] += 1
                if mode == 'missing' and path == '/actions/runs/' + str(cells.SEVENTH_RUN):
                    raise KeyError(path)
                value = self.get(path) if path in self.responses else {'total_count': 24, 'jobs': []}
                if mode == 'incomplete' and path.startswith(origin) and (not path.endswith('1')):
                    value = {'total_count': 24, 'jobs': []}
                if mode == 'bad-count' and path.startswith(origin):
                    value['total_count'] = 25
                seventh = '/actions/runs/' + str(cells.SEVENTH_RUN) + '/attempts/1/jobs?per_page=100&page=1'
                if mode == 'second-readback' and path == seventh and (count[path] == 2):
                    value['jobs'][0]['extra_drift'] = True
                return value
            with self.subTest(mode=mode), ExitStack() as stack:
                state = self.wrapped(stack, barrier=True)
                with self.assertRaises((Denied, KeyError)):
                    f._continuation_native_histories(get, self.descriptor, self.receipt)
                self.assertEqual(state['active'], 0)
                self.assertCountEqual(state['finished'], NAMES)

    def test_real_native_entry_barrier_worker_token_main_only_and_revalidation_no_histories(self):
        raw = b'explicit native model workflow'
        worker = ledger.Worker(995, 78, 1234, 5678, '12345678-1234-4234-8234-123456789abc')
        main = threading.get_ident()
        effects = []
        successor = {'source_sha': 'e' * 40, 'run_id': cells.SEVENTH_RUN + 1, 'reusable_sha': 'f' * 40}
        descriptor = {**self.descriptor, 'successor': successor}
        selected = NS(bootstrap=NS(collector=object(), value={'source_workflow_sha256': hashlib.sha256(raw).hexdigest(), 'source_identity': {'runner_id': 78, 'service_uid': 995}}), identity=NS(required_native_job_name='modeled-current-job'), template_bytes=b'{}')
        who = NS(caller_sha=successor['source_sha'], run_id=successor['run_id'], reusable_sha=successor['reusable_sha'], job_id=123)
        with ExitStack() as stack:
            state = self.wrapped(stack, barrier=True)
            connected, peer = socket.socketpair()
            stack.callback(connected.close)
            stack.callback(peer.close)

            def main_only(label, value):

                def action(*args, **kwargs):
                    self.assertEqual(threading.get_ident(), main)
                    effects.append(label)
                    return value
                return action

            def after(label, value=None):

                def action(*args, **kwargs):
                    self.assertEqual(state['active'], 0)
                    self.assertCountEqual(state['finished'], NAMES)
                    self.assertEqual(threading.get_ident(), main)
                    effects.append(label)
                    return value
                return action

            def read(url, **kwargs):
                path = url.split('/repos/' + f.SOURCE, 1)[1]
                if path.startswith('/contents/'):
                    return ledger.canonical({'type': 'file', 'path': '.github/workflows/collection-ci.yml', 'encoding': 'base64', 'content': base64.b64encode(raw).decode(), 'size': len(raw)})
                if path == '/actions/jobs/123':
                    return ledger.canonical({'id': 123, 'run_id': who.run_id, 'head_sha': who.caller_sha, 'status': 'in_progress', 'conclusion': None, 'name': 'modeled-current-job', 'started_at': '2026-11-16T23:18:15Z'})
                if path == '/git/commits/' + who.caller_sha:
                    return ledger.canonical({'sha': who.caller_sha})
                return ledger.canonical(self.get(path))
            def workflow_assignment(*args, **kwargs):
                result = main_only('worker-token', who)()
                url = f.identity.API + '/repos/' + f.SOURCE + '/contents/.github/workflows/collection-ci.yml?ref=' + result.caller_sha
                return result, f.identity.decode_json(read(url))

            for obj, name, value in [(f.admission, '_secret', main_only('secret', None)), (f, '_controls', main_only('controls', 'same')), (f.collector, 'begin_worker_acquisition', main_only('begin', (worker, object()))), (f.collector, 'finish_worker_acquisition', after('finish', worker)), (f.collector, 'discard_worker_acquisition', main_only('discard', None)), (f.identity, 'verify_github_workflow_assignment', workflow_assignment), (f.identity, 'HTTPSReader', lambda: NS(read=read)), (f, '_continuation_receipt', lambda _: (descriptor, self.receipt, {}, None)), (f, '_continuation_origin_absent', after('absence')), (cells, 'validate_continuation_commit', after('commit'))]:
                stack.enter_context(patch.object(obj, name, value))
            f._native(connected, selected, 'nonce', 'worker-proof-main-only', 'modeled-api')
            self.assertLess(effects.index('absence'), effects.index('commit'))
            self.assertLess(effects.index('commit'), effects.index('finish'))
            self.assertEqual(effects[-1], 'discard')
            started = len(state['started'])
            f._native(connected, selected, 'nonce', 'worker-proof-main-only', 'modeled-api', check_origin=False)
            self.assertEqual(len(state['started']), started)
            original_seventh = copy.deepcopy(self.receipt['native_seventh'])
            seventh_path = '/actions/runs/' + str(cells.SEVENTH_RUN)
            for mode in ['projection', 'helper-read']:
                state['started'].clear()
                state['finished'].clear()
                offset = len(effects)
                if mode == 'projection':
                    self.receipt['native_seventh'] = {'changed': True}
                else:
                    self.receipt['native_seventh'] = original_seventh
                    saved = self.responses.pop(seventh_path)
                with self.subTest(mode=mode), self.assertRaises(Denied if mode == 'projection' else KeyError):
                    f._native(connected, selected, 'nonce', 'worker-proof-main-only', 'modeled-api')
                self.assertEqual(state['active'], 0)
                self.assertCountEqual(state['finished'], NAMES)
                self.assertEqual(effects[-1], 'discard')
                self.assertTrue(set(effects[offset:]).isdisjoint({'absence', 'commit', 'finish'}))
                if mode == 'helper-read':
                    self.responses[seventh_path] = saved
            self.receipt['native_seventh'] = original_seventh


if __name__ == "__main__":
    unittest.main()
