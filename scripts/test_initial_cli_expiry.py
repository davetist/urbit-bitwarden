"""Observe the complete initial CLI lifetime on the owned synthetic ship."""
import json
import time
from api import API
from fixture import NAME, EVIDENCE, owned
from test_initial_cli_token import claims, lifetime


def main():
    assert NAME == 'review-fixes', 'Use the owned review fixture'
    owned(); api = API(); api.bootstrap(); current = None
    try:
        start, _, verifier = api.begin('cli', 'http://localhost:8065', 'api offline_access')
        callback = api.approve(start)
        status, current, _ = api.call('/identity/connect/token', {
            'grant_type': 'authorization_code', 'client_id': 'cli',
            'code': callback['code'][0], 'code_verifier': verifier,
            'redirect_uri': 'http://localhost:8065',
        }, form=True)
        assert status == 200
        payload = lifetime(current, 360)
        began = time.monotonic()
        assert api.call('/api/sync', token=current['access_token'])[0] == 200
        print('Waiting for actual initial CLI expiry; credentials stay private', flush=True)
        while payload['exp'] - time.time() > 5:
            time.sleep(min(30, payload['exp'] - time.time() - 5))
        assert api.call('/api/sync', token=current['access_token'])[0] == 200, 'Initial token expired before its advertised deadline'
        time.sleep(max(0, payload['exp'] - time.time() + 1.5))
        assert api.call('/api/sync', token=current['access_token'])[0] == 401, 'Initial token survived its advertised deadline'
        status, renewed, _ = api.call('/identity/connect/token', {
            'grant_type': 'refresh_token', 'client_id': 'cli',
            'refresh_token': current['refresh_token'],
        }, form=True)
        assert status == 200
        current = renewed; lifetime(current, 60)
        assert api.call('/api/sync', token=current['access_token'])[0] == 200
        result = {'initialLifetimeSeconds': 360, 'acceptedBeforeDeadline': True,
                  'rejectedAfterDeadline': True, 'refreshAfterInitialExpiry': True,
                  'renewedLifetimeSeconds': 60, 'elapsedSeconds': round(time.monotonic() - began, 2)}
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        (EVIDENCE / 'initial-cli-expiry.json').write_text(json.dumps(result, indent=2) + '\n')
        print('PASS actual six-minute initial CLI expiry and 60-second refresh recovery')
    finally:
        if current is not None:
            assert api.call('/identity/connect/revocation', {'token': current['refresh_token']}, form=True)[0] == 200


if __name__ == '__main__': main()
