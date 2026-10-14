"""Official CLI personal types, folders and local export/import round-trip.

Only synthetic records created by this run are exported to a mode-0600 file.
The unfiltered export stays in process memory. The private temporary directory
and its filtered plaintext file are removed on success and on failure.
"""
import copy
import json
import os
import tempfile
import uuid
from pathlib import Path

from fixture import NAME, WORK, EVIDENCE


def assert_fields(actual, expected, path):
    # Official clients add generated metadata such as URI checksums. Verify all
    # supplied plaintext fields recursively without rejecting that metadata.
    if isinstance(expected, dict):
        assert isinstance(actual, dict), ('Personal item structure changed', path)
        for key, value in expected.items():
            assert_fields(actual.get(key), value, path + '.' + key)
    elif isinstance(expected, list):
        assert isinstance(actual, list) and len(actual) == len(expected), ('Personal item list changed', path)
        for index, value in enumerate(expected):
            assert_fields(actual[index], value, path + '[' + str(index) + ']')
    else:
        assert actual == expected, ('Personal item field changed', path)


def assert_item(actual, expected):
    assert actual['name'] == expected['name'], 'Item name did not survive client encryption/decryption'
    assert actual['type'] == expected['type'], 'Personal item type changed'
    assert actual.get('notes') == expected.get('notes'), 'Item notes changed'
    field = {1: 'login', 2: 'secureNote', 3: 'card', 4: 'identity'}[expected['type']]
    assert_fields(actual[field], expected[field], field)


def main():
    if NAME != 'review-fixes':
        raise SystemExit('Use the isolated review fixture')
    # Guard the fixture before importing the helper that reads local credentials.
    from cli_ops import bw, unlock

    unlock()
    bw('sync', raw=True)
    client_version = bw('--version', raw=True)
    marker = 'Native usability ' + uuid.uuid4().hex[:12]
    folder_name = marker + ' renamed folder'
    expected = {}
    owned_items = set()
    owned_folders = set()
    export_path = None
    result = None
    try:
        folder = bw('create', 'folder', bw('encode', input=json.dumps({'name': marker + ' folder'}), raw=True))
        owned_folders.add(folder['id'])
        renamed = bw('edit', 'folder', folder['id'], bw('encode', input=json.dumps({'name': folder_name}), raw=True))
        assert renamed['id'] == folder['id'] and renamed['name'] == folder_name
        assert bw('get', 'folder', folder['id'])['name'] == folder_name

        template = bw('get', 'template', 'item')
        shapes = [
            (1, 'login', {'username': 'synthetic-login', 'password': 'synthetic-client-only-password',
                          'uris': [{'match': None, 'uri': 'https://example.invalid/native-usability'}]}),
            (2, 'secureNote', {'type': 0}),
            (3, 'card', {'cardholderName': 'Synthetic Card', 'brand': 'Visa',
                         'number': '4111111111111111', 'expMonth': '12', 'expYear': '2035', 'code': '123'}),
            (4, 'identity', {'title': 'Mr', 'firstName': 'Synthetic', 'lastName': 'Identity',
                             'email': 'native-usability@example.invalid', 'username': 'synthetic-identity',
                             'company': 'Synthetic example', 'city': 'Example City', 'country': 'ES'}),
        ]
        for kind, field, content in shapes:
            item = copy.deepcopy(template)
            for other in ('login', 'secureNote', 'card', 'identity'):
                item.pop(other, None)
            item.update(name=marker + ' type ' + str(kind), type=kind,
                        notes='Synthetic native personal-vault round-trip', folderId=folder['id'])
            item[field] = content
            created = bw('create', 'item', bw('encode', input=json.dumps(item), raw=True))
            owned_items.add(created['id'])
            expected[created['name']] = item
            assert_item(created, item)
            assert created.get('folderId') == folder['id']
        assert len(owned_items) == 4
        bw('sync', raw=True)
        current = {item['id']: item for item in bw('list', 'items') if item['id'] in owned_items}
        assert len(current) == 4
        for item in current.values():
            assert_item(item, expected[item['name']])
            assert item.get('folderId') == folder['id']
        print('PASS official CLI four personal item types and encrypted folder create/edit/sync', flush=True)

        # The official client decrypts this in memory; never write the whole vault.
        exported = bw('export', '--format', 'json', '--raw')
        filtered = {'encrypted': False,
                    'items': [item for item in exported['items'] if item['id'] in owned_items],
                    'folders': [value for value in exported['folders'] if value['id'] == folder['id']]}
        del exported
        assert len(filtered['items']) == 4 and len(filtered['folders']) == 1
        assert not filtered.get('encrypted', False)
        for item in filtered['items']:
            assert_item(item, expected[item['name']])
        original_ids = set(owned_items)

        bw('delete', 'folder', folder['id'], raw=True)
        owned_folders.remove(folder['id'])
        bw('sync', raw=True)
        detached = [item for item in bw('list', 'items') if item['id'] in original_ids]
        assert len(detached) == 4
        for item in detached:
            assert item.get('folderId') is None, 'Deleting a folder left a stale item association'
            assert_item(item, expected[item['name']])
        for identifier in tuple(original_ids):
            bw('delete', 'item', identifier, '--permanent', raw=True)
            owned_items.remove(identifier)
        print('PASS official CLI folder deletion detaches and preserves all four item types', flush=True)

        with tempfile.TemporaryDirectory(prefix='official-usability-', dir=WORK) as temporary:
            private_dir = Path(temporary)
            assert private_dir.stat().st_mode & 0o777 == 0o700
            export_path = private_dir / 'synthetic-personal-vault.json'
            fd = os.open(export_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as target:
                json.dump(filtered, target)
                target.write('\n')
            assert export_path.stat().st_mode & 0o777 == 0o600
            bw('import', 'bitwardenjson', str(export_path), raw=True)
            bw('sync', raw=True)
            restored = [item for item in bw('list', 'items') if item['name'] in expected]
            owned_items.update(item['id'] for item in restored)
            restored_folders = [value for value in bw('list', 'folders') if value.get('name') == folder_name]
            owned_folders.update(value['id'] for value in restored_folders)
            assert len(restored) == 4 and len(restored_folders) == 1
            assert original_ids.isdisjoint(owned_items), 'Import reused removed item identifiers'
            restored_folder = restored_folders[0]['id']
            assert restored_folder != folder['id'], 'Import reused removed folder identifier'
            for item in restored:
                assert_item(item, expected[item['name']])
                assert item.get('folderId') == restored_folder, 'Imported item lost its restored folder'
        assert not export_path.exists(), 'Task plaintext export was not removed'
        result = {
            'client': 'unmodified official CLI ' + client_version,
            'personal_types_client_encrypt_sync_decrypt': [1, 2, 3, 4],
            'folder_create_rename_read': True,
            'folder_delete_detaches_without_losing_items': True,
            'local_json_export': True,
            'filtered_export_contains_only_four_task_items_and_one_folder': True,
            'official_import_reencrypts_and_restores_all_four_types': True,
            'import_restores_folder_relationships_with_new_ids': True,
            'private_export_mode': '0600 in 0700 task directory',
            'task_plaintext_export_removed': True,
            'request_or_journal_inspection': False,
            'restricted_validation': 'not run',
        }
        print('PASS official CLI local export and import restore four personal types with folder relationships', flush=True)
    finally:
        # Refresh before discovering task records, including an import that may
        # have succeeded just before the CLI process reported an unrelated error.
        bw('sync', raw=True)
        current_items = bw('list', 'items')
        owned_items.update(item['id'] for item in current_items if item.get('name', '').startswith(marker + ' type '))
        current_folders = bw('list', 'folders')
        owned_folders.update(folder['id'] for folder in current_folders
                             if folder.get('id') and folder.get('name', '').startswith(marker + ' '))
        existing_items = {item['id'] for item in current_items}
        for identifier in sorted(owned_items & existing_items):
            bw('delete', 'item', identifier, '--permanent', raw=True)
        existing_folders = {folder['id'] for folder in current_folders if folder.get('id')}
        for identifier in sorted(owned_folders & existing_folders):
            bw('delete', 'folder', identifier, raw=True)
        if export_path is not None:
            assert not export_path.exists(), 'Task plaintext export cleanup failed'
    if result is not None:
        result['task_records_cleaned_up'] = True
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        (EVIDENCE / 'official-cli-usability.json').write_text(json.dumps(result, indent=2) + '\n')
        print('PASS official CLI usability cleanup; unrelated vault records preserved', flush=True)


if __name__ == '__main__':
    main()
