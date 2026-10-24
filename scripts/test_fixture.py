"""Fixture selection and filesystem ownership without touching a live ship."""
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from fixture import ROOT, owned

SCRIPTS = Path(__file__).resolve().parent


class FixtureTests(unittest.TestCase):
    def test_selection_routes_all_shared_paths(self):
        for name, directory, port in [('sso', 'urbitwarden-sso', 19681), ('review-fixes', 'urbitwarden-review-fixes', 19781), ('passkey', 'urbitwarden-passkey', 19881)]:
            with self.subTest(fixture=name):
                result = subprocess.run([sys.executable, '-c',
                    'from fixture import WORK,ORIGIN,EVIDENCE; import json; print(json.dumps([str(WORK),ORIGIN,str(EVIDENCE)]))'],
                    cwd=SCRIPTS, env={**os.environ, 'CONNECT_BW_FIXTURE': name, 'PYTHONDONTWRITEBYTECODE': '1'},
                    capture_output=True, text=True, check=True)
                work, origin, evidence = json.loads(result.stdout)
                self.assertEqual(Path(work), ROOT / '.work' / directory)
                self.assertEqual(origin, f'https://localhost:{port}')
                self.assertEqual(Path(evidence), ROOT / 'evidence' / (name if name != 'sso' else ''))

    def test_unknown_selection_fails_before_work(self):
        result = subprocess.run([sys.executable, '-c', 'import fixture'], cwd=SCRIPTS,
            env={**os.environ, 'CONNECT_BW_FIXTURE': 'unknown', 'PYTHONDONTWRITEBYTECODE': '1'}, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unknown CONNECT_BW_FIXTURE', result.stderr)

    def test_helpers_do_not_bypass_selected_fixture(self):
        # A hard-coded path silently redirects private input/evidence to another
        # fixture. Check every helper used by this plan, including audit children.
        helpers = ['audit.py', 'check_history.py', 'cli_ops.py', 'test_sso_contract.py',
                   'test_adapter.py', 'test_restart.py', 'test_official_negative.py',
                   'test_native_revoke.py', 'test_hardening.py', 'test_pending.py',
                   'probe_sso.py', 'test_native_crypto.py']
        forbidden = ['.work/urbitwarden-sso', 'https://localhost:19681', 'evidence/']
        for name in helpers:
            with self.subTest(helper=name):
                tree = ast.parse((SCRIPTS / name).read_text())
                literals = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
                self.assertFalse([s for s in literals if any(p in s for p in forbidden)], f'{name} bypasses fixture selection')

    def test_ownership_and_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            work = root / 'new'
            self.assertEqual(owned(work, True), work)
            self.assertEqual(owned(work), work)
            other = root / 'other'; other.mkdir()
            (other / 'preserved.txt').write_text('keep')
            with self.assertRaises(ValueError): owned(other, True)
            self.assertEqual((other / 'preserved.txt').read_text(), 'keep')
            link = root / 'link'; link.symlink_to(work, target_is_directory=True)
            with self.assertRaises(ValueError): owned(link)
            (work / '.owned-fixture.json').write_text(json.dumps({'project': 'other'}))
            with self.assertRaises(ValueError): owned(work)

    def test_review_cli_helper_refuses_before_loading_cli_data(self):
        probe = """import importlib.abc, runpy, sys
class BlockCLI(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cli_ops':
            raise RuntimeError('CLI data module imported before fixture selection')
sys.meta_path.insert(0, BlockCLI())
try:
    runpy.run_path('test_official_lifecycle.py', run_name='__main__')
except SystemExit as error:
    if str(error) != 'Use the isolated review fixture': raise
else:
    raise AssertionError('Wrong fixture was accepted')
"""
        result = subprocess.run([sys.executable, '-c', probe], cwd=SCRIPTS,
            env={**os.environ, 'CONNECT_BW_FIXTURE': 'sso', 'PYTHONDONTWRITEBYTECODE': '1'},
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_symlink_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); work = root / 'work'; work.mkdir()
            target = root / 'marker'; target.write_text('{}')
            (work / '.owned-fixture.json').symlink_to(target)
            with self.assertRaises(ValueError): owned(work)


if __name__ == '__main__': unittest.main()
