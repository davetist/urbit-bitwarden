"""Real official CLI encryption, trash, restore and local re-unlock."""
import json
from fixture import NAME, EVIDENCE


def main():
    if NAME != 'review-fixes': raise SystemExit('Use the isolated review fixture')
    from cli_ops import bw, unlock, env
    unlock(); bw('sync', raw=True)
    identifier = None
    try:
        item = bw('get', 'template', 'item')
        item.update(name='Functional restore proof', type=1,
                    login={'username': 'restore-check', 'password': 'synthetic-restore-only', 'uris': []})
        created = bw('create', 'item', bw('encode', input=json.dumps(item), raw=True))
        identifier = created['id']
        bw('delete', 'item', identifier, raw=True); bw('sync', raw=True)
        trash = next(x for x in bw('list', 'items', '--trash') if x['id'] == identifier)
        assert trash['deletedDate'] is not None
        bw('restore', 'item', identifier, raw=True); bw('sync', raw=True)
        restored = bw('get', 'item', identifier)
        assert restored.get('deletedDate') is None
        assert identifier not in [x['id'] for x in bw('list', 'items', '--trash')]
        assert restored['name'] == item['name'] and restored['login']['password'] == item['login']['password']
        bw('lock', raw=True); env.pop('BW_SESSION', None); unlock(); bw('sync', raw=True)
        assert bw('get', 'item', identifier)['login']['password'] == item['login']['password']
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        (EVIDENCE / 'official-cli-lifecycle.json').write_text(json.dumps({
            'client': 'unmodified official CLI 2026.9.1', 'encrypted_create': True,
            'soft_delete_trash': True, 'restore': True, 'sync_and_decrypt': True,
            'lock_and_local_reunlock': True, 'request_or_journal_inspection': False,
        }, indent=2) + '\n')
        print('PASS official CLI encrypted create, trash, restore, sync and local re-unlock')
    finally:
        if identifier is not None: bw('delete', 'item', identifier, '--permanent', raw=True)


if __name__ == '__main__': main()
