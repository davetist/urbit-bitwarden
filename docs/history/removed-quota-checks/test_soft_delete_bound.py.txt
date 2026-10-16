"""Maximum accepted ciphers remain deletable/restorable at the full vault budget."""
from test_cipher_lifecycle import Session, get_item, synchronized, json


def size(item):
    return len(json.dumps(item, separators=(',', ':'), ensure_ascii=False).encode())


def payload_size(item):
    return size({**item, 'deletedDate': None})


def main():
    session = Session()
    created = []
    try:
        existing = session.call('/api/ciphers')[1]['data']
        initial = {item['id']: item for item in existing}
        remaining = 4194304 - sum(payload_size(item) for item in existing)
        assert remaining >= 65536, 'Fixture needs room for a maximum-size cipher'
        # Leave existing fixture data intact; create exactly enough test data to
        # exhaust the payload budget, including a 65,536-byte record.
        while remaining:
            status, item, _ = session.call('/api/ciphers', {'name': '2.boundary'})
            assert status == 200, ('create boundary item', status, remaining)
            created.append(item['id'])
            overhead = size(item) - len(item['name'])
            target = min(65536, remaining)
            if 0 < remaining - target < overhead:
                target = remaining - overhead
            assert target >= overhead, ('unusable remainder', remaining)
            updated = {**item, 'name': 'x' * (target - overhead)}
            status, item, _ = session.call('/api/ciphers/' + item['id'], updated, 'PUT')
            assert status == 200, ('fill boundary item', status, target)
            assert size(item) == target
            remaining -= target
        before = session.call('/api/ciphers')[1]['data']
        assert sum(payload_size(item) for item in before) == 4194304
        item = get_item(session, created[0])
        assert size(item) == 65536
        # Oversized edits and creates must still fail atomically.
        assert session.call('/api/ciphers/' + item['id'], {**item, 'name': item['name'] + 'x'}, 'PUT')[0] == 413
        assert get_item(session, item['id']) == item
        assert session.call('/api/ciphers', {'name': '2.aggregate-overflow'})[0] == 413
        for cipher_id in created:
            assert session.call('/api/ciphers/' + cipher_id + '/delete', {}, 'PUT')[0] == 200, 'Accepted cipher must be deletable at capacity'
        deleted = session.call('/api/ciphers')[1]['data']
        assert len(deleted) == len(before)
        assert sum(payload_size(row) for row in deleted) == 4194304
        assert sum(size(row) for row in deleted) <= 4194304 + 22 * len(deleted)
        maximum = synchronized(session, created[0])
        assert maximum['deletedDate'] is not None and size(maximum) == 65558
        assert maximum['name'] == item['name'], 'Delete must not truncate opaque ciphertext'
        assert session.call('/api/ciphers', {'name': '2.trash-still-counts'})[0] == 413
        # A no-growth update remains possible while tombstones occupy reserve.
        status, same, _ = session.call('/api/ciphers/' + created[0], maximum, 'PUT')
        assert status == 200 and same['name'] == item['name'] and same['deletedDate'] is None
        for cipher_id in created:
            assert session.call('/api/ciphers/' + cipher_id + '/restore', {}, 'PUT')[0] == 200
        restored = session.call('/api/ciphers')[1]['data']
        assert sum(payload_size(row) for row in restored) == 4194304
        assert all(row['deletedDate'] is None for row in restored if row['id'] in created)
        assert {row['id']: row for row in restored if row['id'] in initial} == initial
        print('PASS 65,536-byte cipher and exact 4 MiB vault delete/restore without truncation; bounds remain enforced')
    finally:
        for cipher_id in created:
            assert session.call('/api/ciphers/' + cipher_id, method='DELETE')[0] == 200
        session.close()


if __name__ == '__main__':
    main()
