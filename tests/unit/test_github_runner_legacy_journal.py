"""Synthetic Root-store integration; no native registration or operating grant."""
import hashlib
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

FILES = Path(__file__).resolve().parents[2] / 'roles/github_runner/files'
sys.path.insert(0, str(FILES))
from incus_lease_issuer import registration as reg
from incus_lease_issuer.identity import Denied
from test_github_runner_legacy_registration import locations


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'isolated Root EE fixture only')
class LegacyJournalTests(unittest.TestCase):
    def setUp(self):
        base = Path('/run/proof')
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest('private Root EE tmpfs required')
        self.tmp = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.stage = self.base/'store';self.stage.mkdir(mode=0o700)
        self.target = reg.VerifiedTarget(54334171, 'synthetic-owner', 78, 'incus-runner-01', 6,
            'synthetic-maintenance', 'x64', (('self-hosted','system'),('Linux','system'),('X64','system')),
            '/synthetic/work', 'a'*64, int(time.time())+120, _authority=reg._FENCE_AUTHORITY)
        reg.initialize(str(self.stage), self.target)
        self.key = (self.stage/reg.KEY_FILE).read_bytes()
        self.calls = []
        self.auth_calls = 0
        self.auth_phase = 'auth-intent'
        self.fail = None

    def payload(self):
        return json.loads((self.stage/reg.STATE_FILE).read_bytes())['payload']

    def auth(self, url, token, body):
        self.assertEqual(url, reg.AUTH_URL)
        self.assertEqual(self.payload()['phase'], self.auth_phase)
        self.auth_calls += 1
        if self.fail == 'auth':raise OSError('synthetic-secret')
        return encoded({'url':'https://pipelines.test.actions.githubusercontent.com/tenant/',
                        'token_schema':'OAuthAccessToken','token':'synthetic-tenant-secret'})

    def legacy(self, method, url, token, body, version):
        self.calls.append((method,url))
        self.assertEqual(token, 'synthetic-tenant-secret')
        self.assertEqual(self.payload()['phase'], 'replace-intent' if method == 'PUT' else 'authenticated')
        if method == 'OPTIONS':return encoded(locations())
        if '/pools?' in url:return encoded({'value':[{'id':6,'name':'synthetic-maintenance','isHosted':False}]})
        self.assertIn('/pools/6/agents/78', url)
        value={'id':78,'name':'incus-runner-01','runnerGroupId':6,'runnerGroupName':'synthetic-maintenance',
               'version':'2.338.2','enabled':True,'status':'offline','ephemeral':False,'maxParallelism':1,
               'disableUpdate':False,'authorization':{'clientId':'old-synthetic-client'},'labels':[]}
        if method == 'PUT':
            if self.fail == 'put':raise OSError('synthetic-secret')
            sent=json.loads(body);self.assertEqual(sent['id'],78)
            self.assertTrue(sent['disableUpdate']);self.assertFalse(sent['ephemeral'])
            self.assertEqual(set(sent['authorization']),{'publicKey'})
            value.update(disableUpdate=True,authorization={'clientId':'1439e36e-994c-493c-8834-1e04ac799a21',
                'authorizationUrl':'https://vstoken.actions.githubusercontent.com/_apis/oauth2/token',
                'publicKey':sent['authorization']['publicKey']})
        return encoded(value)

    def apply(self):
        return reg.replace_registration(str(self.stage),self.target,'synthetic-short-token',
                                        _transport=self.auth,_legacy_transport=self.legacy)

    def rejection(self, reason='registration-auth-flow'):
        with reg._stage(str(self.stage)) as fd:
            payload,_=reg._load(fd,self.target)
            payload.update(phase='auth-intent',auth_payload_sha256='b'*64,auth_fence_sha256='a'*64)
            reg._save(fd,payload)
        operator=self.base/'operator.json'
        raw=encoded({'state':'HANDOFF_HELD_NO_AUTOMATIC_RETRY','runner_id':78,'error_type':'Denied',
                     'error_reason':reason,'token_cleanup':True})
        operator.write_bytes(raw);operator.chmod(0o600)
        report={'schema':1,'stage':str(self.stage),'store_id':self.payload()['store_id'],
                'target_sha256':reg._sha(reg._canonical(reg._identity(self.target))),
                'operator_path':str(operator),'operator_sha256':hashlib.sha256(raw).hexdigest()}
        proof=self.base/'rejection.json';proof.write_bytes(encoded(report));proof.chmod(0o600)
        self.auth_phase='auth-reconcile-intent'
        return proof,hashlib.sha256(proof.read_bytes()).hexdigest()

    def resume(self, proof):
        return reg.resume_rejected_legacy_auth(str(self.stage),self.target,'synthetic-short-token',
            str(proof[0]),proof[1],_transport=self.auth,_legacy_transport=self.legacy)

    def prewrite_proof(self, reason='legacy-agent-group'):
        proof=self.rejection()
        with reg._stage(str(self.stage)) as fd:
            payload,_=reg._load(fd,self.target)
            payload.update(phase='authenticated',protocol='legacy',
                tenant_url_sha256=reg._sha(b'https://pipelines.test.actions.githubusercontent.com/tenant/'),
                auth_reconciliation={'original_phase':'auth-intent','evidence_sha256':'c'*64})
            reg._save(fd,payload)
        operator=self.base/'operator.json'
        raw=encoded({'state':'LEGACY_RECOVERY_HELD_NO_AUTOMATIC_RETRY','runner_id':78,
            'error_type':'Denied','error_reason':reason,'token_cleanup':True,'old_service_action':False})
        operator.write_bytes(raw)
        report=json.loads(proof[0].read_bytes());report['operator_sha256']=hashlib.sha256(raw).hexdigest()
        proof[0].write_bytes(encoded(report));self.auth_phase='authenticated'
        return proof[0],hashlib.sha256(proof[0].read_bytes()).hexdigest()

    def resume_prewrite(self, proof):
        return reg.resume_legacy_prewrite_rejection(str(self.stage),self.target,'synthetic-short-token',
            str(proof[0]),proof[1],_transport=self.auth,_legacy_transport=self.legacy)

    def test_prewrite_continuation_preserves_original_intents_and_one_effect(self):
        proof=self.prewrite_proof();original=self.payload()
        self.resume_prewrite(proof)
        self.assertEqual(self.payload()['phase'],'complete')
        self.assertEqual(self.payload()['auth_reconciliation'],original['auth_reconciliation'])
        self.assertEqual(self.payload()['auth_payload_sha256'],original['auth_payload_sha256'])
        self.assertEqual(self.payload()['prewrite_reconciliation']['original_phase'],'authenticated')
        self.resume_prewrite(proof)
        self.assertEqual(self.auth_calls,1);self.assertEqual(len(self.calls),4)
        self.assertEqual((self.stage/reg.KEY_FILE).read_bytes(),self.key)

    def test_prewrite_lost_put_never_retries(self):
        proof=self.prewrite_proof();self.fail='put'
        with self.assertRaises(Denied):self.resume_prewrite(proof)
        self.assertEqual(self.payload()['phase'],'replace-intent')
        with self.assertRaisesRegex(Denied,'registration-prewrite-reconciliation-not-eligible'):
            self.resume_prewrite(proof)
        self.assertEqual(self.auth_calls,1);self.assertEqual(len(self.calls),4)
        self.assertEqual((self.stage/reg.KEY_FILE).read_bytes(),self.key)

    def test_prewrite_auth_failure_does_not_reset_or_consume_credential_effect(self):
        proof=self.prewrite_proof();before=self.payload();self.fail='auth'
        with self.assertRaises(Denied):self.resume_prewrite(proof)
        self.assertEqual(self.payload(),before);self.assertEqual(self.calls,[])
        self.fail=None;self.resume_prewrite(proof)
        self.assertEqual(self.auth_calls,2);self.assertEqual(len(self.calls),4)

    def test_prewrite_wrong_receipt_or_existing_material_denied_before_auth(self):
        proof=self.prewrite_proof(reason='unknown-wire-outcome')
        with self.assertRaisesRegex(Denied,'registration-prewrite-rejection-not-proved'):
            self.resume_prewrite(proof)
        proof=self.prewrite_proof()
        (self.stage/'.runner').write_bytes(b'preserve');(self.stage/'.runner').chmod(0o600)
        with self.assertRaisesRegex(Denied,'registration-stage-inventory|registration-unexpected-material'):self.resume_prewrite(proof)
        self.assertEqual(self.auth_calls,0)

    def test_normal_legacy_success_one_put_and_readonly_completed_reentry(self):
        result=self.apply();self.assertEqual(result.runner_id,78)
        self.assertEqual([x[0] for x in self.calls],['OPTIONS','GET','GET','PUT'])
        self.assertEqual(self.auth_calls,1)
        saved=json.loads((self.stage/'.runner').read_bytes())
        self.assertIs(saved['useRunnerAdminFlow'],False);self.assertIs(saved['useV2Flow'],False)
        self.apply();self.assertEqual(self.auth_calls,1);self.assertEqual(len(self.calls),4)
        self.assertEqual((self.stage/reg.KEY_FILE).read_bytes(),self.key)

    def test_lost_legacy_put_never_retries_or_regenerates_key(self):
        self.fail='put'
        with self.assertRaises(Denied) as error:self.apply()
        self.assertNotIn('synthetic-secret',str(error.exception))
        self.assertEqual(self.payload()['phase'],'replace-intent')
        with self.assertRaisesRegex(Denied,'registration-unknown-held'):self.apply()
        self.assertEqual(self.auth_calls,1);self.assertEqual(len(self.calls),4)
        self.assertEqual((self.stage/reg.KEY_FILE).read_bytes(),self.key)

    def test_explicit_rejected_auth_continuation_preserves_key_and_original_intent(self):
        proof=self.rejection()
        with self.assertRaisesRegex(Denied,'registration-unknown-held'):self.apply()
        self.resume(proof)
        state=self.payload();self.assertEqual(state['phase'],'complete')
        self.assertEqual(state['auth_payload_sha256'],'b'*64)
        self.assertEqual(state['auth_reconciliation']['original_phase'],'auth-intent')
        self.resume(proof);self.assertEqual(self.auth_calls,1);self.assertEqual(len(self.calls),4)
        self.assertEqual((self.stage/reg.KEY_FILE).read_bytes(),self.key)

    def test_unproved_rejection_or_drift_never_authenticates(self):
        proof=self.rejection(reason='registration-http-unknown')
        with self.assertRaisesRegex(Denied,'registration-auth-rejection-not-proved'):self.resume(proof)
        self.assertEqual(self.auth_calls,0);self.assertEqual(self.calls,[])
        with self.assertRaisesRegex(Denied,'registration-rejection-proof-drift'):
            self.resume((proof[0],'0'*64))

    def test_lost_reconcile_auth_keeps_distinct_intent_without_reset_or_retry(self):
        proof=self.rejection();self.fail='auth'
        with self.assertRaises(Denied):self.resume(proof)
        self.assertEqual(self.payload()['phase'],'auth-reconcile-intent')
        with self.assertRaisesRegex(Denied,'registration-reconciliation-not-eligible'):self.resume(proof)
        with self.assertRaisesRegex(Denied,'registration-unknown-held'):self.apply()
        self.assertEqual(self.auth_calls,1);self.assertEqual(self.calls,[])
        self.assertEqual((self.stage/reg.KEY_FILE).read_bytes(),self.key)

    def test_reconcile_put_lost_reply_cannot_enter_reconcile_again(self):
        proof=self.rejection();self.fail='put'
        with self.assertRaises(Denied):self.resume(proof)
        self.assertEqual(self.payload()['phase'],'replace-intent')
        with self.assertRaisesRegex(Denied,'registration-reconciliation-not-eligible'):self.resume(proof)
        self.assertEqual(self.auth_calls,1);self.assertEqual(len(self.calls),4)
        self.assertEqual((self.stage/reg.KEY_FILE).read_bytes(),self.key)


if __name__=='__main__':unittest.main()
