"""Delete/restore contract against real Gall, restricted to the review fixture."""
import os
import time
from api import API, WORK, json


def fixture_only():
    assert os.environ.get('CONNECT_BW_FIXTURE') == 'review-fixes', 'Use the isolated review-fixes fixture'
    assert WORK.name == 'bitwarden-review-fixes', 'Refusing to modify the demo fixture'


class Session:
    def __init__(self):
        fixture_only()
        self.api = API()
        self.api.bootstrap()
        start, _, verifier = self.api.begin('cli', 'http://localhost:8065', 'api offline_access')
        callback = self.api.approve(start)
        status, self.auth, _ = self.api.call('/identity/connect/token', {
            'grant_type': 'authorization_code', 'client_id': 'cli',
            'code': callback['code'][0], 'code_verifier': verifier,
            'redirect_uri': 'http://localhost:8065',
        }, form=True)
        assert status == 200, ('login', status)
        self.started = time.monotonic()

    def call(self, path, data=None, method=None):
        if time.monotonic() - self.started > 35:
            status, self.auth, _ = self.api.call('/identity/connect/token', {
                'grant_type': 'refresh_token', 'client_id': 'cli',
                'refresh_token': self.auth['refresh_token'],
            }, form=True)
            assert status == 200, ('refresh', status)
            self.started = time.monotonic()
        return self.api.call(path, data, method, token=self.auth['access_token'])

    def close(self):
        assert self.api.call('/identity/connect/revocation', {
            'token': self.auth['refresh_token'],
        }, form=True)[0] == 200


def get_item(session, cipher_id):
    status, item, _ = session.call('/api/ciphers/' + cipher_id)
    assert status == 200, ('read cipher', status)
    return item


def synchronized(session, cipher_id):
    status, sync, _ = session.call('/api/sync')
    assert status == 200, ('sync', status)
    return next(item for item in sync['ciphers'] if item['id'] == cipher_id)


def main():
    session = Session()
    cipher_id = None
    try:
        status, item, _ = session.call('/api/ciphers', {'name': '2.lifecycle-preserved', 'notes': '2.opaque-notes', 'type': 1})
        assert status == 200
        cipher_id = item['id']
        path = '/api/ciphers/' + cipher_id
        initial_count = len(session.call('/api/ciphers')[1]['data'])
        # The native client consumes CipherResponse.revisionDate immediately.
        status, response, _ = session.call(path + '/restore', {}, 'PUT')
        assert status == 200, ('restore active cipher', status)
        assert response == item
        for action in ('delete', 'restore'):
            assert session.api.call(path + '/' + action, {}, 'PUT')[0] == 401
            assert session.api.call(path + '/' + action, {}, 'PUT', token='forged')[0] == 401
            assert session.call(path + '/' + action, method='GET')[0] == 405
            assert session.call('/api/ciphers/not-present/' + action, {}, 'PUT')[0] == 404
        assert get_item(session, cipher_id) == item, 'Rejected lifecycle requests must not mutate state'
        # A restore of an active item is already satisfied, without a new revision.
        assert session.call(path + '/restore', {}, 'PUT')[0] == 200
        assert get_item(session, cipher_id) == item
        stamps = [item['revisionDate']]
        for _ in range(4):
            before_revision = session.call('/api/accounts/revision-date')[1]
            assert session.call(path + '/delete', {}, 'PUT')[0] == 200
            deleted = synchronized(session, cipher_id)
            assert deleted['deletedDate'] == deleted['revisionDate']
            assert deleted['revisionDate'] > item['revisionDate']
            assert deleted['name'] == item['name'] and deleted['notes'] == item['notes']
            assert deleted['creationDate'] == item['creationDate']
            deleted_revision = session.call('/api/accounts/revision-date')[1]
            assert deleted_revision > before_revision
            assert len(session.call('/api/ciphers')[1]['data']) == initial_count, 'Trash retains item count'
            assert session.call(path + '/delete', {}, 'PUT')[0] == 200
            assert get_item(session, cipher_id) == deleted, 'Repeated delete must preserve deletion time'
            assert session.call('/api/accounts/revision-date')[1] == deleted_revision
            status, response, _ = session.call(path + '/restore', {}, 'PUT')
            assert status == 200
            restored = synchronized(session, cipher_id)
            assert response == restored, 'Native restore requires the updated CipherResponse'
            assert restored['deletedDate'] is None
            assert restored['revisionDate'] > deleted['revisionDate']
            assert restored['name'] == item['name'] and restored['notes'] == item['notes']
            assert restored['creationDate'] == item['creationDate']
            restored_revision = session.call('/api/accounts/revision-date')[1]
            assert restored_revision > deleted_revision
            assert session.call(path + '/restore', {}, 'PUT')[0] == 200
            assert get_item(session, cipher_id) == restored
            assert session.call('/api/accounts/revision-date')[1] == restored_revision
            stamps.extend([deleted['revisionDate'], restored['revisionDate']])
            item = restored
        assert len(set(stamps)) == len(stamps), 'Every real lifecycle transition needs a distinct revision'
        same_second = any(a[:19] == b[:19] for a, b in zip(stamps, stamps[1:]))
        assert same_second, 'Fixture too slow to demonstrate same-second revisions; repeat this focused test'
        # Revocation blocks both transitions, even though the cipher still exists.
        revoked = Session()
        revoked.close()
        for action in ('delete', 'restore'):
            assert revoked.api.call(path + '/' + action, {}, 'PUT', token=revoked.auth['access_token'])[0] == 401
        assert get_item(session, cipher_id) == item
        print('PASS delete/restore/sync, retained count, same-second revisions, idempotency, authorization')
    finally:
        if cipher_id is not None:
            assert session.call('/api/ciphers/' + cipher_id, method='DELETE')[0] == 200
        session.close()


if __name__ == '__main__':
    main()
