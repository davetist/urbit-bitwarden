import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from migration.source import SourceSet, convert_item
from migration.common import MigrationError


def item(uid='item', **changes):
    value = {'uuid': uid, 'categoryUuid': '001', 'favIndex': 2, 'state': 'active',
             'createdAt': 1, 'updatedAt': 2,
             'overview': {'title': 'Example', 'url': 'https://example.com', 'tags': ['a', 'b']},
             'details': {'notesPlain': 'note\n', 'loginFields': [
                 {'designation': 'username', 'value': 'alice', 'name': 'user'},
                 {'designation': 'password', 'value': 'sensitive-password', 'name': 'pass'}],
                 'sections': [{'title': 'Extra', 'fields': [
                     {'id': 'otp', 'title': 'OTP', 'value': {'totp': 'otpauth://totp/example?secret=AAAA'}},
                     {'id': 'x', 'title': 'Nested', 'value': {'futureType': {'x': [1, False]}}}]}],
                 'passwordHistory': [{'value': str(i), 'time': i+1} for i in range(9)]}}
    value.update(changes)
    return value


def archive(path, items=None, files=None, accounts=None):
    data = {'accounts': accounts or [{'attrs': {'uuid': 'account', 'name': 'Personal'},
        'vaults': [{'attrs': {'uuid': 'vault', 'name': 'Private'}, 'items': items or [item()]}]}]}
    with zipfile.ZipFile(path, 'w') as z:
        z.writestr('export.attributes', json.dumps({'version': 3}))
        z.writestr('export.data', json.dumps(data))
        for name, content in (files or {}).items(): z.writestr(name, content)
    return path


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_duplicate_json_keys_are_rejected(self):
        path=self.root/'duplicate.1pux'
        original=archive(self.root/'original.1pux')
        with zipfile.ZipFile(original) as z: data=z.read('export.data').decode()
        data=data.replace('"uuid": "account"','"uuid": "ignored", "uuid": "account"')
        with zipfile.ZipFile(path,'w') as z:
            z.writestr('export.attributes','{"version":3}')
            z.writestr('export.data',data)
        with self.assertRaises(MigrationError): SourceSet([path])

    def test_full_history_tags_custom_values_and_original_remain(self):
        source = SourceSet([archive(self.root/'a.1pux')])
        record = next(iter(source.records.values()))
        converted = convert_item(record)
        self.assertEqual(converted['login']['password'], 'sensitive-password')
        self.assertEqual(len(converted['passwordHistory']), 9)
        self.assertTrue(converted['favorite'])
        self.assertEqual(converted['notes'], 'note\n')
        values = [f['value'] for f in converted['fields']]
        self.assertIn('["a","b"]', values)
        self.assertIn('{"futureType":{"x":[1,false]}}', values)
        self.assertEqual(record['item'], item())

    def test_empty_web_form_slots_fall_back_to_actual_credential_fields(self):
        value=item()
        for field in value['details']['loginFields']: field['value']=''
        value['details']['sections'][0]['fields'].extend([
            {'id':'username','title':'username','value':{'string':'real-user'}},
            {'id':'password','title':'password','value':{'concealed':'real-password'}}])
        source=SourceSet([archive(self.root/'fallback.1pux',items=[value])])
        login=convert_item(next(iter(source.records.values())))['login']
        self.assertEqual(login['username'],'real-user')
        self.assertEqual(login['password'],'real-password')

    def test_document_binary_zeros_and_same_id_in_different_vaults(self):
        doc = item(categoryUuid='006', details={'documentAttributes': {
            'documentId': 'file-id', 'fileName': 'scan.pdf', 'decryptedSize': 4}})
        accounts = [{'attrs': {'uuid': 'a'}, 'vaults': [
            {'attrs': {'uuid': 'v1'}, 'items': [doc]},
            {'attrs': {'uuid': 'v2'}, 'items': [item()]}]}]
        source = SourceSet([archive(self.root/'a.1pux', accounts=accounts,
                                   files={'files/file-id___scan.pdf': b'\x00a\x00\x00'})])
        self.assertEqual(len(source.records), 2)
        blob = next(b for b in source.blobs.values() if not b['metadata'])
        self.assertEqual(source.read_blob(blob['key']), b'\x00a\x00\x00')
        self.assertEqual(len(blob['owners']), 1)
        self.assertEqual(blob['name'], 'scan.pdf')

    def test_unsafe_archive_and_duplicate_item_fail(self):
        path = archive(self.root/'a.1pux', files={'../escape': b'secret'})
        with self.assertRaises(MigrationError): SourceSet([path])
        path = archive(self.root/'b.1pux', items=[item(), item()])
        with self.assertRaises(MigrationError): SourceSet([path])

    def test_missing_document_is_not_silently_skipped(self):
        doc = item(details={'documentAttributes': {'documentId': 'gone', 'fileName': 'missing.pdf'}})
        source = SourceSet([archive(self.root/'a.1pux', items=[doc])])
        self.assertTrue(source.blockers)

    def test_unknown_category_preserves_all_fields_as_note_and_reports_mapping(self):
        source = SourceSet([archive(self.root/'a.1pux', items=[item(categoryUuid='future')])])
        record = next(iter(source.records.values()))
        self.assertEqual(convert_item(record)['type'], 2)
        self.assertTrue(record['representation'])

    def test_ssh_private_material_survives_conversion(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        from migration.common import item_projection
        key=ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        pem=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
        ssh=item(categoryUuid='114',details={'sections':[{'title':'SSH','fields':[{'id':'key','title':'Private',
            'value':{'sshKey':{'metadata':{'privateKey':pem}}}}]}]})
        source=SourceSet([archive(self.root/'ssh.1pux',items=[ssh])]); record=next(iter(source.records.values()))
        a=convert_item(record); b=convert_item(record)
        restored=serialization.load_ssh_private_key(a['sshKey']['privateKey'].encode(),password=None)
        self.assertEqual(restored.private_bytes_raw(),key.private_bytes_raw())
        self.assertEqual(item_projection(a),item_projection(b))


if __name__ == '__main__': unittest.main()
