"""Offline lifecycle and acceptance regressions; never open the user's fixture."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'scripts'


class BitwardenToolingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bw-', dir='/private/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.scripts = self.root / 'scripts'
        self.scripts.mkdir(parents=True)
        for name in ('connect_dependency', 'fixture', 'install', 'start', 'stop', 'setup', 'cli_sso'):
            shutil.copyfile(SCRIPTS / (name + '.py'), self.scripts / (name + '.py'))
        self.work = self.root / '.work/bitwarden-sso'
        self.work.mkdir(parents=True)
        (self.work / '.owned-fixture.json').write_text(json.dumps({
            'project': str(self.root), 'fixture': 'native-bitwarden-sso-v1'}))
        self.env = {**os.environ, 'CONNECT_BW_FIXTURE': 'sso'}
        self.vere = self.root / '.work/toolchains/vere-4.6/vere-v4.6-macos-aarch64'
        self.vere.parent.mkdir(parents=True)
        self.vere.write_text('#!' + sys.executable + '\n' + '''
import os, pathlib, socket, sys, time
from http.server import HTTPServer, BaseHTTPRequestHandler
pier = pathlib.Path(sys.argv[-1]); (pier/'.urb').mkdir(parents=True, exist_ok=True)
(pier.parent/'spawned.pid').write_text(str(os.getpid()))
time.sleep(float(os.environ.get('FAKE_DELAY', '0')))
if os.environ.get('FAKE_NEVER_READY'):
    time.sleep(60)
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(str(pier/'.urb/conn.sock')); server.listen()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302 if os.environ.get('FAKE_REDIRECT') else 200)
        self.send_header('Location', 'https://localhost:1/'); self.end_headers(); self.wfile.write(b'ready')
    def log_message(self, *args): pass
HTTPServer(('127.0.0.1', int(sys.argv[sys.argv.index('--http-port')+1])), Handler).serve_forever()
''')
        self.vere.chmod(0o700)
        (self.scripts / 'control.py').write_text('raise SystemExit("offline control unavailable")\n')
        (self.scripts / 'api.py').write_text("from fixture import ROOT, WORK\nORIGIN='https://localhost:19681'\n")

    def run_code(self, code, **env):
        return subprocess.run([sys.executable, '-c', code], cwd=self.scripts,
                              env={**self.env, **env}, capture_output=True, text=True, timeout=15)

    def port(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            return listener.getsockname()[1]

    def start_code(self, timeout):
        return (f'import fixture; fixture.HTTP_PORT={self.port()}; '
                f'fixture.HTTPS_PORT={self.port()}; fixture.AMES_PORT={self.port()}; '
                f'import start; start.start(timeout={timeout})')

    def assert_dead(self, pid):
        result = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='], capture_output=True, text=True)
        self.assertTrue(not result.stdout.strip() or result.stdout.strip().startswith('Z'), result.stdout)

    def clean_process(self):
        pidfile = self.work / 'spawned.pid'
        if pidfile.exists():
            try: os.kill(int(pidfile.read_text()), 9)
            except ProcessLookupError: pass

    def test_review_fixture_is_separate_and_unknown_selector_refused(self):
        r = self.run_code('from fixture import *; print(WORK.name, ORIGIN, HTTP_PORT, AMES_PORT)',
                          CONNECT_BW_FIXTURE='review-fixes')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), 'bitwarden-review-fixes https://localhost:19781 19780 19782')
        r = self.run_code('import fixture', CONNECT_BW_FIXTURE='../bitwarden-sso')
        self.assertNotEqual(r.returncode, 0)

    def test_start_waits_for_service_and_stop_terminates_without_socket(self):
        self.addCleanup(self.clean_process)
        start = time.monotonic()
        r = self.run_code(self.start_code(4), FAKE_DELAY='0.4')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertGreaterEqual(time.monotonic() - start, .4)
        pid = int((self.work / 'runtime.pid').read_text())
        (self.work / 'pier/.urb/conn.sock').unlink()
        r = self.run_code('import stop; stop.stop(timeout=.2)')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assert_dead(pid)

    def test_failed_control_is_reported_and_owned_process_is_terminated(self):
        self.addCleanup(self.clean_process)
        r = self.run_code(self.start_code(4))
        self.assertEqual(r.returncode, 0, r.stderr)
        pid = int((self.work / 'runtime.pid').read_text())
        r = self.run_code('import stop; stop.stop(timeout=.2)')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('control', r.stderr.lower())
        self.assert_dead(pid)

    def test_https_redirect_is_ready_without_following_untrusted_tls(self):
        self.addCleanup(self.clean_process)
        r = self.run_code(self.start_code(4), FAKE_REDIRECT='1')
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.run_code('import stop; stop.stop(timeout=.1)')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_unready_start_fails_and_reaps_its_process(self):
        self.addCleanup(self.clean_process)
        r = self.run_code(self.start_code(.3), FAKE_NEVER_READY='1')
        self.assertNotEqual(r.returncode, 0)
        pid = int((self.work / 'spawned.pid').read_text())
        self.assert_dead(pid)

    def test_reused_pid_identity_cannot_stop_unrelated_process(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        self.addCleanup(lambda: child.poll() is None and child.kill())
        (self.work / 'runtime.pid').write_text(str(child.pid))
        (self.work / 'runtime-process.json').write_text(json.dumps({
            'pid': child.pid, 'started': 'not its birth time', 'command': 'not its command'}))
        r = self.run_code('import stop; stop.stop(timeout=.1)')
        self.assertNotEqual(r.returncode, 0)
        self.assertIsNone(child.poll())
        child.terminate(); child.wait(timeout=3)

    def test_setup_failure_stops_the_process_it_started(self):
        self.addCleanup(self.clean_process)
        code = f"""
import fixture
fixture.HTTP_PORT={self.port()}; fixture.HTTPS_PORT={self.port()}; fixture.AMES_PORT={self.port()}
import setup, start, stop
from unittest.mock import patch
def run(script, *args):
    if script == 'start.py': start.start(timeout=4)
    elif script == 'stop.py': stop.stop(timeout=.1)
    else: raise RuntimeError('deliberate preparation failure')
with patch.object(setup, 'prepare'), patch.object(setup, 'run', run):
    try: setup.main()
    except RuntimeError as error:
        assert str(error) == 'deliberate preparation failure'
    else: raise AssertionError('setup falsely succeeded')
"""
        r = self.run_code(code)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assert_dead(int((self.work / 'spawned.pid').read_text()))

    def test_installer_encodes_source_bytes_under_minimum_python(self):
        source = self.root / 'source'; source.mkdir()
        (source / 'main.hoon').write_text('a' * 1234)
        (source / 'label.txt').write_text('ñ')
        code = """
import install
from pathlib import Path
requests = []
install.control = requests.append
install.install('bitwarden', Path('../source').resolve())
assert len(requests) == 4
assert '/main/hoon %ins %hoon val' in requests[1]
assert '/text/plain [1.234 0x' in requests[1]
assert '/label/txt %ins %txt val' in requests[2]
assert '/text/plain [2 0xb1c3]' in requests[2]
"""
        r = self.run_code(code)
        self.assertEqual(r.returncode, 0, r.stderr)

    def make_cli(self):
        cli = self.work / 'vendor/cli/bw'; cli.parent.mkdir(parents=True)
        cli.write_text('#!' + sys.executable + '\n' + '''
import json, os, sys
from pathlib import Path
if sys.argv[1]=='status':
    print(json.dumps({'status': os.environ.get('FAKE_CLI_STATUS', 'unauthenticated')}))
elif sys.argv[1]=='login':
    Path(os.environ['BITWARDENCLI_APPDATA_DIR']).mkdir(exist_ok=True)
    raise SystemExit(int(os.environ.get('FAKE_CLI_EXIT', '0')))
''')
        cli.chmod(0o700)

    def test_failed_official_login_propagates_exit_status(self):
        self.make_cli()
        r = self.run_code('import runpy; runpy.run_path("cli_sso.py", run_name="__main__")', FAKE_CLI_EXIT='17')
        self.assertEqual(r.returncode, 17, r.stderr)
        self.assertEqual(json.loads((self.work / 'cli-login-result.json').read_text())['returncode'], 17)

    def test_old_logged_in_profile_cannot_count_as_new_acceptance(self):
        self.make_cli()
        (self.work / 'cli-login-result.json').write_text('{"returncode":0}')
        r = self.run_code('import runpy; runpy.run_path("cli_sso.py", run_name="__main__")', FAKE_CLI_STATUS='locked')
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.work / 'cli-profile').exists())
        self.assertFalse((self.work / 'cli-login-result.json').exists())


if __name__ == '__main__': unittest.main()
