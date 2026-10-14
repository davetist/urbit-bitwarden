"""Standalone source/dependency checks; no existing ships or private fixtures."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import connect_dependency as dependency
import package


def git(root, *args):
    return subprocess.run(['git', *args], cwd=root, check=True,
                          capture_output=True, text=True).stdout.strip()


class RepositoryLayoutTests(unittest.TestCase):
    def test_managed_source_follows_latest_main(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); upstream = root / 'upstream'; upstream.mkdir()
            git(upstream, 'init', '-b', 'main')
            git(upstream, 'config', 'user.name', 'Local test')
            git(upstream, 'config', 'user.email', 'test@example.invalid')
            git(upstream, 'config', 'commit.gpgsign', 'false')
            source = upstream / 'desk/app/connect.hoon'; source.parent.mkdir(parents=True)
            source.write_text('first source')
            git(upstream, 'add', 'desk'); git(upstream, 'commit', '-m', 'test: first source')
            cache = root / 'cache/connect'
            with patch.multiple(dependency, CONNECT_ROOT=cache, BUNDLED=root / 'bundled',
                                OVERRIDE=None, REPOSITORY=upstream.as_uri()):
                dependency.ensure_connect(refresh=True)
                self.assertEqual((cache / 'desk/app/connect.hoon').read_text(), 'first source')
                source.write_text('latest source')
                git(upstream, 'add', 'desk'); git(upstream, 'commit', '-m', 'test: latest source')
                dependency.ensure_connect(refresh=True)
                self.assertEqual(git(cache, 'rev-parse', 'HEAD'), git(upstream, 'rev-parse', 'HEAD'))
                self.assertEqual((cache / 'desk/app/connect.hoon').read_text(), 'latest source')

    def test_developer_checkout_and_extracted_bundle_are_read_only_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); (root / 'desk/app').mkdir(parents=True)
            (root / 'desk/app/connect.hoon').write_text('selected source')
            for override, bundled in [(str(root), root / 'unused'), (None, root)]:
                with self.subTest(override=override), patch.multiple(
                        dependency, CONNECT_ROOT=root, OVERRIDE=override, BUNDLED=bundled), \
                        patch.object(dependency, 'git') as run:
                    self.assertEqual(dependency.ensure_connect(refresh=True), root)
                    run.assert_not_called()

    def test_source_bundle_uses_standalone_layout_and_excludes_build_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); (root / 'scripts').mkdir()
            (root / 'scripts/main.py').write_text('source')
            for name in ['__pycache__/main.pyc', 'node_modules/dependency.js', '.work/private.txt', 'dist/output.txt']:
                path = root / 'scripts' / name; path.parent.mkdir(parents=True); path.write_text('not source')
            entries = package.sources(root, ['scripts'])
            self.assertEqual(entries, {'scripts/main.py': b'source'})
            self.assertEqual(package.build(entries), package.build(entries))


if __name__ == '__main__': unittest.main()
