"""Run a new official CLI SSO login; an existing session is not acceptance."""
import os
import subprocess
import json
from fixture import WORK, ORIGIN, owned


def main():
    owned()
    bw = str(WORK / 'vendor/cli/bw')
    env = {**os.environ, 'BITWARDENCLI_APPDATA_DIR': str(WORK / 'cli-profile'),
           'NODE_EXTRA_CA_CERTS': str(WORK / 'tls/cert.pem'),
           'BITWARDENCLI_DISABLE_UPDATE_NOTIFIER': 'true',
           'PATH': str(WORK / 'bin') + os.pathsep + os.environ['PATH']}
    result = WORK / 'cli-login-result.json'
    result.unlink(missing_ok=True)
    (WORK / 'cli-browser-url.json').unlink(missing_ok=True)
    status = subprocess.run([bw, 'status'], env=env, capture_output=True, text=True)
    if status.returncode or json.loads(status.stdout).get('status') != 'unauthenticated':
        raise SystemExit('CLI profile is already authenticated or unreadable; preserve it and use a fresh fixture for new acceptance.')
    config = subprocess.run([bw, 'config', 'server', ORIGIN], env=env, capture_output=True, text=True)
    if config.returncode: raise SystemExit('CLI configuration failed')
    # SSO requires an interactive terminal. Parent starts this script with a PTY.
    login = subprocess.run([bw, 'login', '--sso', 'urbit-vault'], env=env, capture_output=True, text=True)
    result.write_text(json.dumps({'returncode': login.returncode, 'stdout': login.stdout, 'stderr': login.stderr}))
    result.chmod(0o600)
    print('Official CLI SSO exit:', login.returncode)
    return login.returncode


if __name__ == '__main__': raise SystemExit(main())
