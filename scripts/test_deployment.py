"""Installer contract tests; synthetic files and control replies, no real ships."""
import hashlib
import json
import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import deploy
from noun import cell, jam


class DeploymentTests(unittest.TestCase):
    def source(self, root):
        files = {'dependencies/urbit-connect/desk/app/connect.hoon': b'connect source',
                 'dependencies/urbit-connect/desk/desk.bill': b'~[%connect]',
                 'desk/app/urbitwarden.hoon': b'vault source',
                 'desk/desk.bill': b'~[%urbitwarden]'}
        for prefix in ('dependencies/urbit-connect/desk/', 'desk/'):
            for mark in ('noun', 'hoon', 'txt', 'kelvin'):
                files[prefix + 'mar/' + mark + '.hoon'] = b'fixture mark source'
            files[prefix + 'sys.kelvin'] = b'[%zuse 408]'
        for name, value in files.items():
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(value)
        (root / 'INTEGRATION-MANIFEST.json').write_text(json.dumps({
            name: hashlib.sha256(value).hexdigest() for name, value in files.items()}))
        return files

    def test_source_requires_complete_unchanged_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); files = self.source(root)
            release = deploy.load_source(root)
            self.assertEqual(set(release['desks']), {'connect', 'urbitwarden'})
            self.assertEqual(sum(len(entries) for entries in release['desks'].values()), len(files))
            (root / 'dependencies/urbit-connect/desk/app/connect.hoon').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'hash'): deploy.load_source(root)

    def test_source_refuses_unlisted_files_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); self.source(root)
            extra = root / 'dependencies/urbit-connect/desk/unlisted.hoon'; extra.write_text('not in package')
            with self.assertRaisesRegex(ValueError, 'manifest'): deploy.load_source(root)
            extra.unlink(); extra.symlink_to(root / 'dependencies/urbit-connect/desk/app/connect.hoon')
            with self.assertRaisesRegex(ValueError, 'symlink'): deploy.load_source(root)

    def test_source_root_alias_resolves_but_descendant_links_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); root = base / 'source'; root.mkdir()
            self.source(root)
            alias = base / 'selected-source'; alias.symlink_to(root, target_is_directory=True)
            self.assertEqual(deploy.load_source(alias), deploy.load_source(root))
            source = root / 'dependencies/urbit-connect/desk/app/connect.hoon'; raw = source.read_bytes(); source.unlink()
            elsewhere = base / 'external.hoon'; elsewhere.write_bytes(raw); source.symlink_to(elsewhere)
            with self.assertRaisesRegex(ValueError, 'symlink'): deploy.load_source(alias)

    def test_source_size_and_count_budgets_reject_untrusted_plan_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); self.source(root)
            cases = [
                ('MAX_MANIFEST_BYTES', 16, 'manifest.*limit'),
                ('MAX_MANIFEST_ENTRIES', 2, 'manifest.*entry limit'),
                ('MAX_SOURCE_PATHS', 2, 'path limit'),
                ('MAX_SOURCE_FILES', 2, 'file limit'),
                ('MAX_SOURCE_FILE_BYTES', 4, 'file.*byte limit'),
                ('MAX_SOURCE_TOTAL_BYTES', 16, 'total.*byte limit'),
            ]
            for name, limit, message in cases:
                with self.subTest(limit=name), patch.object(deploy, name, limit, create=True):
                    with self.assertRaisesRegex(ValueError, message):
                        deploy.load_source(root)

    def test_source_exact_size_limits_preserve_normal_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); files = self.source(root)
            manifest_size = (root / 'INTEGRATION-MANIFEST.json').stat().st_size
            paths = sum(1 for desk in ('desk', 'dependencies/urbit-connect/desk')
                        for _ in (root / desk).rglob('*'))
            limits = {'MAX_MANIFEST_BYTES': manifest_size,
                      'MAX_MANIFEST_ENTRIES': len(files), 'MAX_SOURCE_PATHS': paths,
                      'MAX_SOURCE_FILES': len(files),
                      'MAX_SOURCE_FILE_BYTES': max(map(len, files.values())),
                      'MAX_SOURCE_TOTAL_BYTES': sum(map(len, files.values()))}
            with contextlib.ExitStack() as stack:
                for name, value in limits.items(): stack.enter_context(patch.object(deploy, name, value, create=True))
                self.assertEqual(sum(map(len, deploy.load_source(root)['desks'].values())), len(files))

    def test_wide_source_directory_stops_scanning_at_path_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); self.source(root)
            desk = root / 'dependencies/urbit-connect/desk'
            for index in range(30): (desk / ('extra' + str(index))).mkdir()
            scanned = 0
            original = os.scandir

            class CountingScan:
                def __init__(self, path): self.iterator = original(path)
                def __enter__(self): self.iterator.__enter__(); return self
                def __exit__(self, *args): return self.iterator.__exit__(*args)
                def __iter__(self): return self
                def __next__(self):
                    nonlocal scanned
                    entry = next(self.iterator); scanned += 1
                    return entry

            with patch.object(deploy.os, 'scandir', CountingScan), \
                    patch.object(deploy, 'MAX_SOURCE_PATHS', 3):
                with self.assertRaisesRegex(ValueError, 'path limit'):
                    deploy.load_source(root)
            self.assertLessEqual(scanned, 4)

    def test_valid_pier_accepts_selected_runtime_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); pier = base / 'pier'; (pier / '.urb').mkdir(parents=True)
            runtime = base / 'runtime'; runtime.write_bytes(b'packaged runtime'); runtime.chmod(0o755)
            (pier / '.run').symlink_to(runtime)
            self.assertEqual(deploy.validate_pier(pier), pier)
            runtime.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'executable'): deploy.validate_pier(pier)

    def test_origin_has_no_credentials_or_paths(self):
        self.assertEqual(deploy.validate_origin('https://ship.example/'), 'https://ship.example')
        for bad in ['http://ship.example', 'https://a:b@ship.example', 'https://ship.example/path',
                    'https://ship.example/#fragment', 'https://ship.example:0', 'https://ship.example?x=1']:
            with self.subTest(bad=bad), self.assertRaises(ValueError): deploy.validate_origin(bad)

    def test_routes_keep_root_and_other_apps_but_refuse_shadowing(self):
        harmless = [{'path': '/', 'site': None, 'app': 'landscape'},
                    {'path': '/apps/notes', 'site': None, 'app': 'notes'}]
        deploy.check_routes(harmless, 'https://ship.example')
        for path in ['/apps/urbitwarden', '/apps/urbitwarden/api', '/connect', '/apps/connect']:
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'route'):
                deploy.check_routes(harmless + [{'path': path, 'site': None, 'app': 'other'}], 'https://ship.example')
        deploy.check_routes([{'path': '/apps/urbitwarden', 'site': None, 'app': 'urbitwarden'}], 'https://ship.example')

    def test_existing_desks_require_exact_update_selection(self):
        status = {'ship': '~sampel-palnet', 'desks': ['connect'], 'routes': []}
        with self.assertRaisesRegex(ValueError, 'update-existing'):
            deploy.check_target(status, '~sampel-palnet', 'https://ship.example', False)
        deploy.check_target(status, '~sampel-palnet', 'https://ship.example', True)
        with self.assertRaisesRegex(ValueError, 'identity'):
            deploy.check_target(status, '~other-planet', 'https://ship.example', True)

    def test_plan_never_mutates_and_apply_installs_both_selected_desks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); self.source(root)
            release = deploy.load_source(root)
            control = Mock(); control.inspect.return_value = {'ship': '~sampel-palnet', 'desks': [], 'routes': []}
            result = deploy.deploy(control, release, '~sampel-palnet', 'https://ship.example', apply=False)
            self.assertEqual(result['urbitwardenURL'], 'https://ship.example/apps/urbitwarden')
            control.run.assert_not_called()
            deploy.deploy(control, release, '~sampel-palnet', 'https://ship.example', apply=True)
            expressions = [call.args[0] for call in control.run.call_args_list]
            self.assertTrue(any('%kiln-install' in text and '%connect' in text for text in expressions))
            self.assertTrue(any('%kiln-install' in text and '%urbitwarden' in text for text in expressions))
            self.assertTrue(all('~zod' not in text for text in expressions))

    def test_empty_historical_names_require_explicit_reuse_and_reseed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); self.source(root)
            release = deploy.load_source(root)
            control = Mock()
            control.inspect.return_value = {'ship': '~sampel-palnet', 'desks': ['connect'],
                                            'legacyDesk': True, 'routes': []}
            control.inert_desk.side_effect = lambda _, desk: desk in {'connect', 'bitwarden'}
            with self.assertRaisesRegex(ValueError, 'Existing %bitwarden vault'):
                deploy.deploy(control, release, '~sampel-palnet', 'https://ship.example')
            control.run.assert_not_called()
            result = deploy.deploy(control, release, '~sampel-palnet', 'https://ship.example',
                                   reuse_empty_history=True)
            self.assertEqual(result['inertHistoricalDesks'], ['bitwarden', 'connect'])
            control.run.assert_not_called()
            deploy.deploy(control, release, '~sampel-palnet', 'https://ship.example',
                          apply=True, reuse_empty_history=True)
            expressions = [call.args[0] for call in control.run.call_args_list]
            self.assertTrue(any('new-desk:cloy %connect' in text and
                                '~(has in .^((set desk)' not in text for text in expressions))
            control.inert_desk.side_effect = lambda _, desk: desk == 'connect'
            with self.assertRaisesRegex(ValueError, 'Existing %bitwarden vault'):
                deploy.deploy(control, release, '~sampel-palnet', 'https://ship.example',
                              reuse_empty_history=True)

    def test_inert_desk_requires_files_stopped_status_and_missing_gall_state(self):
        control = deploy.Control.__new__(deploy.Control)
        control.run = Mock(side_effect=[0, 0, RuntimeError('missing target'), 0])
        self.assertTrue(control.inert_desk('~sampel-palnet', 'bitwarden'))
        self.assertEqual(control.run.call_count, 4)
        control.run = Mock(side_effect=[1, 0])
        self.assertFalse(control.inert_desk('~sampel-palnet', 'bitwarden'))
        control.run = Mock(side_effect=[0, 0, 0])
        self.assertFalse(control.inert_desk('~sampel-palnet', 'bitwarden'))

    def test_control_decode_returns_only_success_payload(self):
        encoded = jam(cell(0, 'avow', 0, 'noun', 42))
        self.assertEqual(deploy.control_result(encoded), 42)
        with self.assertRaisesRegex(RuntimeError, 'failed'):
            deploy.control_result(jam(cell(0, 'avow', 1, 'failed')))

    def test_tls_only_changes_certificate_without_importing_desks(self):
        control = Mock()
        control.inspect.return_value = {'ship': '~sampel-palnet'}
        argv = ['deploy.py', '--pier', '/chosen/pier', '--ship', '~sampel-palnet',
                '--origin', 'https://ship.example', '--tls-only', '--cert', '/chosen/cert',
                '--key', '/chosen/key', '--apply', '--apply-tls']
        with patch('sys.argv', argv), patch('deploy.Control', return_value=control), \
                patch('deploy.tls_expression', return_value='chosen TLS request'), \
                patch('deploy.load_source') as source, contextlib.redirect_stdout(io.StringIO()):
            deploy.main()
        source.assert_not_called()
        control.run.assert_called_once_with('chosen TLS request')

    def test_bad_selection_fails_before_native_work(self):
        for ship in ['zod', '~zod \n(poke)', '~bad_thing']:
            with self.assertRaises(ValueError): deploy.validate_ship(ship)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'pier'; path.mkdir()
            with self.assertRaisesRegex(ValueError, 'pier'): deploy.validate_pier(path)


if __name__ == '__main__': unittest.main()
