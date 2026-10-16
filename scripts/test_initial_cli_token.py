"""Native issuance/expiry contract for the official CLI's early-refresh window.

Runs on the selected owned, enrolled review fixture. Only this test's sessions
are revoked; no stored credential state or journal is inspected or exported.
"""
import base64
import json
import time
from api import API
from fixture import NAME, EVIDENCE, owned


def claims(response):
    return json.loads(base64.urlsafe_b64decode(response['access_token'].split('.')[1] + '==='))


def lifetime(response, seconds):
    payload = claims(response)
    assert response['expires_in'] == seconds, 'Token response lifetime differs'
    assert payload['exp'] - payload['iat'] == seconds, 'JWT lifetime differs'
    return payload


def main():
    assert NAME == 'review-fixes', 'Use the owned review fixture'
    owned(); api = API(); api.bootstrap()
    current = {}
    def exchange(client, redirect):
        start, _, verifier = api.begin(client, redirect, 'api offline_access')
        callback = api.approve(start)
        status, response, _ = api.call('/identity/connect/token', {
            'grant_type': 'authorization_code', 'client_id': client,
            'code': callback['code'][0], 'code_verifier': verifier, 'redirect_uri': redirect,
        }, form=True)
        assert status == 200, ('code exchange', client, status)
        current[client] = response
        return response
    def refresh(client):
        status, response, _ = api.call('/identity/connect/token', {
            'grant_type': 'refresh_token', 'client_id': client,
            'refresh_token': current[client]['refresh_token'],
        }, form=True)
        assert status == 200, ('refresh', client, status)
        current[client] = response
        return response
    def sync(response):
        return api.call('/api/sync', token=response['access_token'])[0]
    def after_expiry(response):
        time.sleep(max(0, claims(response)['exp'] - time.time() + 1.5))
    try:
        first = exchange('cli', 'http://localhost:8065')
        assert claims(first)['exp'] - time.time() > 300, 'Fresh CLI token is already inside the five-minute refresh window'
        lifetime(first, 360)
        assert refresh('cli') == first, 'Immediate retry did not retain the identical response'
        assert sync(first) == 200
        status, body, _ = api.call('/connect/owner/v1/clients', owner=True)
        assert status == 200
        clients = {client['id']: client for client in body['clients']}
        others = [exchange(client, clients[client]['redirectURI']) for client in ('browser', 'desktop', 'mobile')]
        for response in others:
            lifetime(response, 60)
            assert sync(response) == 200
        after_expiry(max(others, key=lambda response: claims(response)['exp']))
        assert all(sync(response) == 401 for response in others), 'Non-CLI server expiry changed'
        assert sync(first) == 200, 'Initial CLI server expiry is still 60 seconds'
        renewed = refresh('cli')
        lifetime(renewed, 60)
        assert renewed != first and sync(renewed) == 200
        assert sync(first) == 401, 'Rotation did not replace the initial bearer'
        after_expiry(renewed)
        assert sync(renewed) == 401, 'Refreshed CLI server expiry is not 60 seconds'
        lifetime(refresh('cli'), 60)
        assert sync(current['cli']) == 200
        sid = claims(current['cli'])['sid']
        assert api.call('/connect/owner/v1/revoke', {'sessionId': sid}, owner=True)[0] == 200
        assert sync(current['cli']) == 401, 'Owner revocation did not deny access'
        assert api.call('/identity/connect/token', {
            'grant_type': 'refresh_token', 'client_id': 'cli',
            'refresh_token': current['cli']['refresh_token'],
        }, form=True)[0] == 400, 'Owner revocation did not deny refresh'
        result = {'initialCLISeconds': 360, 'initialCLIOutsideFiveMinuteWindow': True,
                  'immediateRetryResponseIdentical': True, 'otherClientSeconds': 60,
                  'otherClientExpiryEnforced': True, 'initialCLIAccessAfter60Seconds': True,
                  'renewedCLISeconds': 60, 'renewedCLIExpiryEnforced': True,
                  'refreshAfterExpiry': True, 'oldBearerReplacedOnRotation': True,
                  'ownerRevocationDeniesAccessAndRefresh': True}
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        (EVIDENCE / 'initial-cli-token.json').write_text(json.dumps(result, indent=2) + '\n')
        print('PASS initial CLI exception, other-client and refreshed-token expiry, retry and owner revocation')
    finally:
        for response in current.values():
            assert api.call('/identity/connect/revocation', {'token': response['refresh_token']}, form=True)[0] == 200


if __name__ == '__main__': main()
