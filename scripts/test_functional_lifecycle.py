"""Positive delete/restore lifecycle; adversarial authorization checks stay separate."""
from test_cipher_lifecycle import Session, get_item, synchronized, json
from fixture import EVIDENCE


def main():
    session = Session(); identifier = None
    try:
        status, item, _ = session.call('/api/ciphers', {'name': '2.functional-lifecycle', 'notes': '2.opaque-notes', 'type': 1})
        assert status == 200
        identifier = item['id']; path = '/api/ciphers/' + identifier
        count = len(session.call('/api/ciphers')[1]['data'])
        assert session.call(path + '/restore', {}, 'PUT')[1] == item
        stamps = [item['revisionDate']]
        for _ in range(4):
            previous = session.call('/api/accounts/revision-date')[1]
            assert session.call(path + '/delete', {}, 'PUT')[0] == 200
            deleted = synchronized(session, identifier)
            assert deleted['deletedDate'] == deleted['revisionDate'] > item['revisionDate']
            assert (deleted['name'], deleted['notes'], deleted['creationDate']) == (item['name'], item['notes'], item['creationDate'])
            assert len(session.call('/api/ciphers')[1]['data']) == count
            assert session.call('/api/accounts/revision-date')[1] > previous
            assert session.call(path + '/delete', {}, 'PUT')[0] == 200
            assert get_item(session, identifier) == deleted
            status, restored, _ = session.call(path + '/restore', {}, 'PUT')
            assert status == 200 and restored == synchronized(session, identifier)
            assert restored['deletedDate'] is None and restored['revisionDate'] > deleted['revisionDate']
            assert (restored['name'], restored['notes'], restored['creationDate']) == (item['name'], item['notes'], item['creationDate'])
            previous = session.call('/api/accounts/revision-date')[1]
            assert session.call(path + '/restore', {}, 'PUT')[1] == restored
            assert session.call('/api/accounts/revision-date')[1] == previous
            stamps.extend([deleted['revisionDate'], restored['revisionDate']]); item = restored
        assert len(set(stamps)) == len(stamps)
        assert any(a[:19] == b[:19] for a, b in zip(stamps, stamps[1:])), 'Same-second revision case not exercised'
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        (EVIDENCE / 'functional-lifecycle.json').write_text(json.dumps({
            'cycles': 4, 'restore_response': True, 'ciphertext_preserved': True,
            'idempotent': True, 'same_second_monotonic_revisions': True,
            'trash_count_preserved': True, 'adversarial_authorization_checks': 'deferred',
        }, indent=2) + '\n')
        print('PASS 4 delete/restore/sync cycles, exact responses, idempotency and same-second revisions')
    finally:
        if identifier is not None: assert session.call('/api/ciphers/' + identifier, method='DELETE')[0] == 200
        session.close()


if __name__ == '__main__': main()
