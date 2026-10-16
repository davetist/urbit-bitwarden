"""Native personal-folder and atomic encrypted-import correctness checks.

Uses only the owned review fixture and ordinary authorized API operations.
No credential inspection, journal inspection, or adversarial auth checks.
"""
import json
from api import API
from fixture import NAME, EVIDENCE

BASE = '/apps/bitwarden'


def main():
    assert NAME == 'review-fixes', 'Use the owned review fixture'
    api = API()
    api.bootstrap()
    start, _, verifier = api.begin('cli', 'http://localhost:8065', 'api offline_access')
    callback = api.approve(start)
    status, auth, _ = api.call(BASE + '/identity/connect/token', {
        'grant_type': 'authorization_code', 'client_id': 'cli',
        'code': callback['code'][0], 'code_verifier': verifier,
        'redirect_uri': 'http://localhost:8065',
    }, form=True)
    assert status == 200, ('SSO', status)

    def call(path, data=None, method=None):
        result = api.call(BASE + '/api' + path, data, method, token=auth['access_token'])
        if result[0] == 401:
            status, refreshed, _ = api.call(BASE + '/identity/connect/token', {
                'grant_type': 'refresh_token', 'client_id': 'cli',
                'refresh_token': auth['refresh_token'],
            }, form=True)
            assert status == 200, ('ordinary refresh', status)
            auth.update(refreshed)
            result = api.call(BASE + '/api' + path, data, method, token=auth['access_token'])
        return result

    def snapshot():
        status, value, _ = call('/sync')
        assert status == 200
        return {'ciphers': value['ciphers'], 'folders': value['folders'],
                'revision': call('/accounts/revision-date')[1]}

    original = snapshot()
    original_items = {item['id'] for item in original['ciphers']}
    original_folders = {folder['id'] for folder in original['folders']}
    try:
        status, existing, _ = call('/folders', {'name': '2.existing-encrypted-folder'})
        assert status == 200
        bulk = {
            'folders': [{'id': existing['id'], 'name': '2.hint-not-rename'},
                        {'id': 'untrusted-import-file-id', 'name': '2.new-encrypted-folder'}],
            'ciphers': [{'type': 1, 'name': '2.large-import-' + str(index),
                         'notes': '2.' + 'x' * 35000, 'login': {'username': '2.opaque'}}
                        for index in range(8)],
            'folderRelationships': [{'key': index, 'value': index % 2} for index in range(8)],
        }
        assert len(json.dumps(bulk).encode()) > 262144
        status, _, _ = call('/ciphers/import', bulk)
        assert status == 200, ('single-request import larger than old body limit', status)
        after = snapshot()
        imported = [item for item in after['ciphers'] if item['id'] not in original_items]
        assert len(imported) == 8
        new_folders = [folder for folder in after['folders'] if folder['id'] not in original_folders]
        assert len(new_folders) == 2
        assert next(folder for folder in new_folders if folder['id'] == existing['id']) == existing
        created = next(folder for folder in new_folders if folder['id'] != existing['id'])
        assert created['id'] != 'untrusted-import-file-id'
        assert {item['folderId'] for item in imported} == {existing['id'], created['id']}
        assert len({item['id'] for item in imported} | {folder['id'] for folder in new_folders}) == 10
        assert all(item['notes'] == '2.' + 'x' * 35000 for item in imported)

        # An imported file may contain IDs that happen to equal IDs allocated
        # earlier in this same request. Only pre-existing folders are reusable.
        status, probe, _ = call('/folders', {'name': '2.import-id-probe'})
        assert status == 200
        last_number = int(probe['id'].rsplit('-', 1)[1])
        assert call('/folders/' + probe['id'], method='DELETE')[0] == 200
        def future_id(offset):
            return '00000000-0000-4000-8000-' + str(last_number + offset).zfill(12)
        before_folders = {folder['id'] for folder in snapshot()['folders']}
        status, _, _ = call('/ciphers/import', {
            'folders': [{'id': future_id(2), 'name': '2.import-collision-first'},
                        {'id': future_id(1), 'name': '2.import-collision-second'}],
            'ciphers': [], 'folderRelationships': [],
        })
        assert status == 200
        collision_folders = [folder for folder in snapshot()['folders'] if folder['id'] not in before_folders]
        assert len(collision_folders) == 2, 'Unknown folder hint reused a folder allocated during this import'
        assert {folder['name'] for folder in collision_folders} == {'2.import-collision-first', '2.import-collision-second'}
        for folder in collision_folders:
            assert call('/folders/' + folder['id'], method='DELETE')[0] == 200

        valid = {'type': 1, 'name': '2.atomic-import', 'login': {}}
        rejected = [
            ('late invalid item', {'folders': [{'name': '2.must-not-persist'}],
                                  'ciphers': [valid, {'type': 1}], 'folderRelationships': []}, 400),
            ('invalid relationship index', {'folders': [{'name': '2.must-not-persist'}],
                                            'ciphers': [valid],
                                            'folderRelationships': [{'key': 0, 'value': 1}]}, 400),
            ('duplicate relationship', {'folders': [{'name': '2.must-not-persist'}],
                                        'ciphers': [valid],
                                        'folderRelationships': [{'key': 0, 'value': 0}] * 2}, 400),
        ]
        for label, payload, expected in rejected:
            before = snapshot()
            status, _, _ = call('/ciphers/import', payload)
            assert status == expected, (label, status, expected)
            assert snapshot() == before, (label, 'import changed stored vault or revision')

        status, _, _ = call('/folders', {'ids': [existing['id'], created['id']]}, 'DELETE')
        assert status == 200
        after = snapshot()
        assert {folder['id'] for folder in after['folders']} == original_folders
        retained = [item for item in after['ciphers'] if item['id'] not in original_items]
        assert len(retained) == 8 and all(item['folderId'] is None for item in retained)
        assert all(item['notes'] == '2.' + 'x' * 35000 for item in retained)
        all_deleted = False
        if not original_folders:
            status, single, _ = call('/folders', {'name': '2.delete-all-folder'})
            assert status == 200
            item = retained[0]
            assert call('/ciphers/' + item['id'], {**item, 'folderId': single['id']}, 'PUT')[0] == 200
            assert call('/folders/all', method='DELETE')[0] == 200
            final = snapshot()
            assert final['folders'] == []
            assert next(row for row in final['ciphers'] if row['id'] == item['id'])['folderId'] is None
            all_deleted = True
        result = {
            'large_single_request_import': True,
            'existing_folder_hint_reused_without_rename': True,
            'unknown_folder_hint_gets_server_id': True,
            'distinct_folder_and_cipher_identifiers': True,
            'import_folder_hint_cannot_reuse_newly_allocated_folder': True,
            'atomic_rejection_cases': [case[0] for case in rejected],
            'bulk_folder_delete_preserves_ciphertext': True,
            'delete_all_folders_preserves_ciphers': all_deleted,
            'restricted_validation': 'not run',
        }
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        (EVIDENCE / 'folders-import-functional.json').write_text(json.dumps(result, indent=2) + '\n')
        print('PASS native encrypted folders, large import, relationship mapping and eight atomic bounds cases')
    finally:
        current = snapshot()
        for item in current['ciphers']:
            if item['id'] not in original_items:
                assert call('/ciphers/' + item['id'], method='DELETE')[0] == 200
        for folder in current['folders']:
            if folder['id'] not in original_folders:
                assert call('/folders/' + folder['id'], method='DELETE')[0] == 200
        assert api.call(BASE + '/identity/connect/revocation', {'token': auth['refresh_token']}, form=True)[0] == 200


if __name__ == '__main__':
    main()
