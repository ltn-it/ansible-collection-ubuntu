"""Guard against false passes in password-free and incomplete audit subjects."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

SOURCE = Path(__file__).resolve().parents[2] / 'roles/cis_ubuntu24/files/password_policy_audit.py'
SPEC = importlib.util.spec_from_file_location('password_policy_audit', SOURCE)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class PasswordPolicyTests(unittest.TestCase):
    defaults = {'PASS_MAX_DAYS': 365, 'PASS_WARN_AGE': 7}

    def statuses(self, accounts, defaults=None):
        return [x['status'] for x in AUDIT.evaluate(self.defaults if defaults is None else defaults, accounts, 365, 7)['results']]

    def test_no_password_subjects_still_checks_global_policy(self):
        report = AUDIT.evaluate(self.defaults, [{'status': 'L'}] * 3, 365, 7)
        self.assertEqual(report['eligible_password_account_count'], 0)
        self.assertEqual(report['password_account_subjects'], 'not_applicable_no_password_accounts')
        self.assertEqual([x['status'] for x in report['results']], ['pass', 'pass'])
        self.assertEqual(self.statuses([{'status': 'L'}], {'PASS_MAX_DAYS': 99999, 'PASS_WARN_AGE': 7}), ['fail', 'pass'])

    def test_unlocked_password_limits_and_missing_metadata_fail(self):
        for account, expected in [
            ({'status': 'P', 'max_days': 365, 'warn_days': 7}, ['pass', 'pass']),
            ({'status': 'P', 'max_days': 99999, 'warn_days': 7}, ['fail', 'pass']),
            ({'status': 'P', 'max_days': -1, 'warn_days': 7}, ['fail', 'pass']),
            ({'status': 'P', 'max_days': 365, 'warn_days': 6}, ['pass', 'fail']),
            ({'status': 'P'}, ['fail', 'fail']),
            ({'status': 'NP'}, ['fail', 'fail']),
            ({'status': 'unknown'}, ['fail', 'fail'])]:
            with self.subTest(account=account):
                self.assertEqual(self.statuses([account]), expected)

    def test_duplicates_and_incomplete_defaults_are_not_passes(self):
        with self.assertRaises(ValueError):
            AUDIT.login_defaults('PASS_MAX_DAYS 365\nPASS_MAX_DAYS 99999\n')
        self.assertEqual(self.statuses([{'status': 'L'}], {'PASS_MAX_DAYS': 365}), ['pass', 'fail'])
        self.assertEqual(AUDIT.login_defaults('# comment\nPASS_MAX_DAYS 365 # reviewed\nPASS_WARN_AGE 7\n'), self.defaults)

    def test_native_chage_output_requires_both_numeric_fields(self):
        text = 'Maximum number of days between password change : 365\nNumber of days of warning before password expires : 7\n'
        self.assertEqual(AUDIT.aging_fields(text), {'max_days': 365, 'warn_days': 7})
        with self.assertRaises(ValueError):
            AUDIT.aging_fields('Maximum number of days between password change : never\n')

    def test_locked_accounts_never_need_a_shadow_or_chage_read(self):
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            self.assertEqual(argv[:2], ['/usr/bin/passwd', '--status'])
            return SimpleNamespace(returncode=0, stdout=argv[2] + ' L 01/01/2026 0 99999 7 -1\n')
        self.assertEqual(AUDIT.collect_accounts([SimpleNamespace(pw_name='fixture')], run), [{'status': 'L'}])
        self.assertEqual(len(calls), 1)

    def test_failed_or_wrong_subject_native_queries_fail_closed(self):
        for result in [SimpleNamespace(returncode=1, stdout=''), SimpleNamespace(returncode=0, stdout='wrong P')]:
            with self.subTest(result=result), self.assertRaises(ValueError):
                AUDIT.collect_accounts([SimpleNamespace(pw_name='fixture')], lambda *a, **k: result)

    def test_invalid_policy_cannot_create_supplemental_pass(self):
        for maximum, warning in [(366, 7), (True, 7), (365, 6), (365, False)]:
            with self.subTest(policy=(maximum, warning)), self.assertRaises(ValueError):
                AUDIT.evaluate(self.defaults, [{'status': 'L'}], maximum, warning)


if __name__ == '__main__':
    unittest.main()
