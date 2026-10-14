"""Legitimate refresh retries and restart compatibility on the owned fake ship."""
import concurrent.futures
import json
from pathlib import Path
import subprocess
import sys
import time
from api import API
from fixture import NAME, WORK, EVIDENCE, owned


def main():
    assert NAME == 'review-fixes', 'Use the owned review fixture'
    owned(); api = API(); api.bootstrap()
    start, _, verifier = api.begin('cli', 'http://localhost:8065', 'api offline_access')
    callback = api.approve(start)
    status, current, _ = api.call('/identity/connect/token', {
        'grant_type': 'authorization_code', 'client_id': 'cli',
        'code': callback['code'][0], 'code_verifier': verifier,
        'redirect_uri': 'http://localhost:8065',
    }, form=True)
    assert status == 200, ('login', status)
    scripts = Path(__file__).resolve().parent
    def refresh(value):
        return api.call('/identity/connect/token', {
            'grant_type': 'refresh_token', 'client_id': 'cli', 'refresh_token': value['refresh_token']
        }, form=True)
    try:
        time.sleep(5.2)
        previous = current
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            responses = list(pool.map(lambda _: refresh(previous), range(6)))
        assert all(result[0] == 200 for result in responses), 'Concurrent legitimate retry failed'
        current = responses[0][1]
        assert all(result[1] == current for result in responses), 'Retry response changed'
        latency = time.monotonic() - started
        assert api.call('/api/sync', token=current['access_token'])[0] == 200
        # Expiring a response must not expire the current refresh credential.
        time.sleep(5.2)
        previous = current
        status, current, _ = refresh(previous)
        assert status == 200, ('refresh after idle cache expiry', status)
        started = time.monotonic()
        for script in ('stop.py', 'start.py'):
            subprocess.run([sys.executable, str(scripts / script)], check=True, timeout=60)
        elapsed = time.monotonic() - started
        inside_grace = elapsed < 5
        # Outside grace, use the current credential; do not exercise stale-token
        # rejection or replay attacks in this functionality-only check.
        status, after, _ = refresh(previous if inside_grace else current)
        assert status == 200, ('refresh after restart', status)
        if inside_grace: assert after == current, 'Restart changed the cached retry response'
        current = after
        assert api.call('/api/sync', token=current['access_token'])[0] == 200
        evidence = {'concurrent_retries': 6, 'identical_response': True,
                    'six_retry_seconds': latency, 'current_refresh_survives_cache_expiry': True,
                    'restart_seconds': elapsed, 'identical_response_across_restart_demonstrated': inside_grace,
                    'post_restart_sync': True, 'security_replay_tests': 'deferred'}
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        (EVIDENCE / 'refresh-compatibility.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print('PASS legitimate refresh compatibility;', json.dumps(evidence))
    finally:
        assert api.call('/identity/connect/revocation', {'token': current['refresh_token']}, form=True)[0] == 200


if __name__ == '__main__': main()
