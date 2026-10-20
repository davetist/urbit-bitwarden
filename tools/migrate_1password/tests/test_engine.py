import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from migration.common import MigrationError, read_json, write_json, MARKER
from migration.engine import Engine
from test_source import archive, item


def passkey(number=1):
    key = ec.derive_private_key(number, ec.SECP256R1())
    raw = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return {'credentialId': 'b64.' + base64.urlsafe_b64encode(bytes([number])*16).decode().rstrip('='),
            'keyValue': base64.urlsafe_b64encode(raw).decode().rstrip('='), 'keyType':'public-key',
            'keyAlgorithm':'ECDSA', 'keyCurve':'P-256', 'rpId':'example.com', 'userHandle':'YWxpY2U',
            'userName':'alice', 'userDisplayName':'Alice', 'discoverable':'true', 'counter':'0'}


class MemoryVault:
    """Stateful test double for the external CLI boundary; no ship or network is opened."""
    def __init__(self):
        self.data={}; self.folder_data={}; self.bytes={}; self.sequence=0; self.fail_after=None
    def next(self): self.sequence+=1; return str(self.sequence)
    def bind(self, expected_user=None):
        if expected_user and expected_user!='user': raise MigrationError('wrong user')
        return 'user'
    def sync(self): pass
    def items(self): return copy.deepcopy(list(self.data.values()))
    def folders(self): return copy.deepcopy(list(self.folder_data.values()))
    def get_item(self, key): return copy.deepcopy(self.data[key])
    def create_folder(self, name):
        value={'id':self.next(),'name':name}; self.folder_data[value['id']]=value; return copy.deepcopy(value)
    def create_item(self, payload):
        value=copy.deepcopy(payload); value.update(id=self.next(), revisionDate='revision', attachments=[])
        self.data[value['id']]=value
        if self.fail_after=='create': self.fail_after=None; raise MigrationError('response lost')
        return copy.deepcopy(value)
    def edit_item(self, key, payload):
        self.data[key].update(copy.deepcopy(payload)); return self.get_item(key)
    def upload(self, key, path):
        identifier=self.next(); self.bytes[(key,identifier)]=Path(path).read_bytes()
        self.data[key]['attachments'].append({'id':identifier,'fileName':Path(path).name})
        if self.fail_after=='upload': self.fail_after=None; raise MigrationError('response lost')
        return self.get_item(key)
    def download(self, key, attachment): return self.bytes[(key,attachment)]


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.work=self.root/'private'
        doc=item(details={**item()['details'], 'documentAttributes':{
            'documentId':'doc','fileName':'file.bin','decryptedSize':4}})
        self.source=archive(self.root/'source.1pux',items=[doc],files={'files/doc___file.bin':b'\x00a\x00\xff'})
        self.vault=MemoryVault()

    def prepare(self, keys=0):
        engine=Engine.prepare(self.work,[self.source],'https://ship.invalid/apps/urbitwarden','me@example.invalid')
        self.source_id=next(iter(engine.source.records))
        entries=[]
        for index in range(keys):
            value={'name':'Example','type':1,'login':{'username':'alice','password':'sensitive-password',
                    'fido2Credentials':[passkey(index+1)]},'fields':[]}
            created=self.vault.create_item(value)
            entries.append({'item_id':created['id'],'credential_id':passkey(index+1)['credentialId'],
                            'sign_in_verified':True})
        engine.capture(self.vault)
        review=read_json(self.work/'review.json')
        review.update(source_scope_reviewed=True, passkey_inventory_reviewed=True,
                      representations_reviewed=True, expected_passkey_count=keys,
                      cross_client_sync_verified=True, passkeys={self.source_id:entries} if keys else {})
        write_json(self.work/'review.json',review)
        return engine

    def test_wrong_destination_identity_prevents_apply(self):
        engine=self.prepare(); engine.plan(self.vault); engine.state['user_id']='another-user'; engine.save()
        with self.assertRaises(MigrationError): engine.apply(self.vault)
        self.assertFalse(self.vault.data)

    def test_complete_native_files_passkeys_and_source_are_preserved(self):
        before=self.source.read_bytes(); engine=self.prepare(keys=2)
        engine.plan(self.vault); engine.apply(self.vault)
        report=engine.verify(self.vault)
        self.assertTrue(report['complete'],report)
        self.assertEqual(report['passkey_occurrences_verified'],2)
        self.assertEqual(report['files_verified'],3)
        self.assertEqual(self.source.read_bytes(),before)
        self.assertEqual(len(self.vault.data),3)  # two credential items and source metadata
        serialized=json.dumps(read_json(self.work/'state.json'))+json.dumps(report)
        self.assertNotIn('sensitive-password',serialized)
        self.assertNotIn(passkey()['keyValue'],serialized)

    def test_unknown_create_outcome_resumes_without_duplicate(self):
        engine=self.prepare(); engine.plan(self.vault); self.vault.fail_after='create'
        with self.assertRaises(MigrationError): engine.apply(self.vault)
        Engine(self.work).apply(self.vault)
        self.assertEqual(len(self.vault.data),2)
        self.assertTrue(Engine(self.work).verify(self.vault)['complete'])

    def test_unknown_attachment_outcome_resumes_without_duplicate(self):
        engine=self.prepare(); engine.plan(self.vault); self.vault.fail_after='upload'
        with self.assertRaises(MigrationError): engine.apply(self.vault)
        Engine(self.work).apply(self.vault)
        self.assertEqual(len(self.vault.bytes),3)

    def test_tampered_file_native_value_and_missing_passkey_fail_verification(self):
        engine=self.prepare(keys=1); engine.plan(self.vault); engine.apply(self.vault)
        key=next(iter(self.vault.bytes)); self.vault.bytes[key]=b'corrupt'
        native=next(v for v in self.vault.data.values() if v.get('type')==1)
        native['login']['password']='changed'; native['login']['fido2Credentials']=[]
        report=engine.verify(self.vault)
        self.assertFalse(report['complete']); self.assertTrue(report['issues'])

    def test_unreviewed_passkey_coverage_blocks_writes(self):
        engine=self.prepare(); review=read_json(self.work/'review.json')
        review['passkey_inventory_reviewed']=False; write_json(self.work/'review.json',review)
        with self.assertRaises(MigrationError): engine.plan(self.vault)
        self.assertFalse(self.vault.data)

    def test_destination_edit_after_plan_is_not_overwritten(self):
        engine=self.prepare(keys=1); engine.plan(self.vault)
        self.vault.data['1']['notes']='a new user change'
        with self.assertRaises(MigrationError): engine.apply(self.vault)
        self.assertEqual(self.vault.data['1']['notes'],'a new user change')

    def test_source_change_is_refused(self):
        engine=self.prepare(); engine.plan(self.vault)
        archive(self.source,items=[item('different')])
        with self.assertRaises(MigrationError): Engine(self.work)

    def test_folder_rename_fails_verification(self):
        engine=self.prepare(); engine.plan(self.vault); engine.apply(self.vault)
        next(iter(self.vault.folder_data.values()))['name']='changed folder'
        self.assertFalse(engine.verify(self.vault)['complete'])

    def test_passkey_counter_change_is_allowed_but_key_change_is_not(self):
        engine=self.prepare(keys=1); engine.plan(self.vault); engine.apply(self.vault)
        self.vault.data['1']['login']['fido2Credentials'][0]['counter']='5'
        self.assertTrue(engine.verify(self.vault)['complete'])
        self.vault.data['1']['login']['fido2Credentials'][0]['keyValue']=passkey(2)['keyValue']
        self.assertFalse(engine.verify(self.vault)['complete'])

    def test_completed_apply_is_idempotent(self):
        engine=self.prepare(keys=1); engine.plan(self.vault); engine.apply(self.vault)
        before=copy.deepcopy(self.vault.data)
        self.assertTrue(Engine(self.work).apply(self.vault)['complete'])
        self.assertEqual(self.vault.data,before)

    def test_stale_owned_scratch_is_removed_on_resume_without_touching_sources(self):
        engine=self.prepare(); scratch=self.work/'.upload-interrupted'; scratch.mkdir(mode=0o700)
        (scratch/'payload').write_bytes(b'temporary secret')
        state=read_json(self.work/'state.json'); state['scratch']=[str(scratch)]; write_json(self.work/'state.json',state)
        Engine(self.work)
        self.assertFalse(scratch.exists()); self.assertTrue(self.source.exists())

    def test_scratch_cleanup_refuses_external_or_symlink_paths(self):
        engine=self.prepare(); target=self.root/'outside'; target.mkdir()
        link=self.work/'.upload-linked'; link.symlink_to(target,target_is_directory=True)
        state=read_json(self.work/'state.json'); state['scratch']=[str(link)]; write_json(self.work/'state.json',state)
        with self.assertRaises(MigrationError): Engine(self.work)
        self.assertTrue(target.exists())

    def test_missing_user_checks_cannot_be_mistaken_for_complete(self):
        engine=self.prepare(keys=1); engine.plan(self.vault); engine.apply(self.vault)
        review=read_json(self.work/'review.json'); review['cross_client_sync_verified']=False
        review['passkeys'][self.source_id][0]['sign_in_verified']=False
        write_json(self.work/'review.json',review)
        report=engine.verify(self.vault)
        self.assertFalse(report['complete'])
        self.assertEqual(report['passkey_occurrences_verified'],1)

    def test_multiple_keys_in_one_cxp_item_are_never_removed_from_it(self):
        engine=self.prepare(keys=1)
        self.vault.data['1']['login']['fido2Credentials'].append(passkey(2))
        engine.capture(self.vault)
        review=read_json(self.work/'review.json'); review['expected_passkey_count']=2
        review['passkeys'][self.source_id].append({'item_id':'1','credential_id':passkey(2)['credentialId'],'sign_in_verified':True})
        write_json(self.work/'review.json',review)
        engine.plan(self.vault); engine.apply(self.vault)
        self.assertEqual(len(self.vault.data['1']['login']['fido2Credentials']),2)
        self.assertEqual(len(self.vault.data),4)
        self.assertTrue(engine.verify(self.vault)['complete'])

    def test_existing_marker_cannot_authorize_dropping_unreviewed_passkey(self):
        engine=self.prepare()
        source_id=next(iter(engine.source.records))
        value={'name':'Example','type':1,'login':{'username':'alice','password':'sensitive-password',
            'fido2Credentials':[passkey()]},'fields':[{'name':MARKER,'value':source_id,'type':1}]}
        existing=self.vault.create_item(value)
        with self.assertRaises(MigrationError): engine.plan(self.vault)
        self.assertEqual(len(self.vault.data[existing['id']]['login']['fido2Credentials']),1)

    def test_marked_multi_key_target_cannot_be_narrowed_to_one(self):
        engine=self.prepare(keys=1)
        self.vault.data['1']['fields'].append({'name':MARKER,'value':self.source_id,'type':1})
        self.vault.data['1']['login']['fido2Credentials'].append(passkey(2))
        engine.capture(self.vault)
        with self.assertRaises(MigrationError): engine.plan(self.vault)
        self.assertEqual(len(self.vault.data['1']['login']['fido2Credentials']),2)

    def test_runtime_workspace_cannot_be_created_inside_a_git_checkout(self):
        checkout=self.root/'checkout'; checkout.mkdir(); (checkout/'.git').mkdir()
        with self.assertRaises(MigrationError):
            Engine.prepare(checkout/'private',[self.source],'https://ship.invalid/apps/urbitwarden','me@example.invalid')


if __name__=='__main__': unittest.main()
