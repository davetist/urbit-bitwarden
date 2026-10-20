"""Encryption and publication checks; native restoration has its own rehearsal."""
import importlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.key = self.root / 'identity.txt'
        generated = subprocess.run(['age-keygen', '-o', str(self.key)], capture_output=True)
        self.assertEqual(generated.returncode, 0)
        self.recipient = subprocess.check_output(['age-keygen', '-y', str(self.key)], text=True).strip()
        self.backup = importlib.import_module('vault_backup')

    def test_encrypted_roundtrip_is_private_and_no_plaintext_file(self):
        payload = b'wrapped-key and synthetic encrypted passkey material'
        target = self.root / 'backup.age'
        self.backup.seal(payload, target, self.recipient)
        self.assertNotIn(payload, target.read_bytes())
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.backup.unseal(target, self.key), payload)
        self.assertEqual({p.name for p in self.root.iterdir()}, {'identity.txt', 'backup.age'})

    def test_corruption_and_wrong_key_are_rejected(self):
        target = self.root / 'backup.age'
        self.backup.seal(b'synthetic snapshot', target, self.recipient)
        other = self.root / 'other.txt'
        subprocess.run(['age-keygen', '-o', str(other)], capture_output=True, check=True)
        with self.assertRaises(RuntimeError):
            self.backup.unseal(target, other)
        raw = bytearray(target.read_bytes()); raw[-1] ^= 1; target.write_bytes(raw)
        with self.assertRaises(RuntimeError):
            self.backup.unseal(target, self.key)

    def test_existing_backup_and_symlink_are_not_overwritten(self):
        target = self.root / 'backup.age'
        target.write_bytes(b'existing')
        with self.assertRaises(FileExistsError):
            self.backup.seal(b'new', target, self.recipient)
        self.assertEqual(target.read_bytes(), b'existing')
        link = self.root / 'link.age'; link.symlink_to(target)
        with self.assertRaises((ValueError, FileExistsError)):
            self.backup.seal(b'new', link, self.recipient)
        self.assertEqual(target.read_bytes(), b'existing')

    def test_socket_capture_does_not_require_a_docked_executable(self):
        import socket
        import deploy
        pier = self.root / 'pier'; (pier / '.urb').mkdir(parents=True)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(pier / '.urb/conn.sock'))
            with self.assertRaises(ValueError):
                deploy.Control(pier)
            self.assertEqual(deploy.Control(pier, require_runtime=False).pier, pier)

    def test_schedule_reuses_unchanged_capture_and_retries_failed_upload(self):
        import json
        import socket
        from unittest.mock import patch
        pier = self.root / 'pier'; (pier / '.urb').mkdir(parents=True)
        config = self.root / 'config.json'
        config.write_text(json.dumps({'pier': str(pier), 'ship': '~zod',
            'recipient': self.recipient, 'output': str(self.root / 'snapshots'),
            'remote': 'test:backups', 'rcloneConfig': str(self.root / 'rclone.conf')}))
        payload = json.dumps({'sha256': 'a' * 64, 'snapshot': 'synthetic ciphertext'}).encode()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(pier / '.urb/conn.sock'))
            with patch.object(self.backup, 'capture', return_value=payload):
                with patch.object(self.backup, 'upload', side_effect=RuntimeError('offline')):
                    with self.assertRaises(RuntimeError): self.backup.scheduled(config)
                self.assertEqual(len(list((self.root / 'snapshots').glob('*.age'))), 1)
                self.assertEqual(list((self.root / 'snapshots').glob('*.uploaded.json')), [])
                self.assertFalse((self.root / 'snapshots/status.json').exists())
                with patch.object(self.backup, 'upload', side_effect=lambda target, remote, config: remote + '/' + target.name):
                    result = self.backup.scheduled(config)
                    self.assertTrue(result['cloudConfigured'])
                    self.assertTrue(result['unchanged'])
                    self.assertEqual(result['uploaded'], 1)
                    second = self.backup.scheduled(config)
                    self.assertTrue(second['unchanged'])
                    self.assertEqual(second['uploaded'], 0)
                    settings = json.loads(config.read_text()); settings['remote'] = 'other:backups'
                    config.write_text(json.dumps(settings))
                    moved = self.backup.scheduled(config)
                    self.assertTrue(moved['unchanged'])
                    self.assertEqual(moved['uploaded'], 1)
                self.assertEqual(len(list((self.root / 'snapshots').glob('*.age'))), 1)
                self.assertEqual(len(list((self.root / 'snapshots').glob('*.uploaded.json'))), 1)

    def test_new_content_replaces_only_latest_archive(self):
        import json
        import socket
        from unittest.mock import patch
        pier = self.root / 'pier'; (pier / '.urb').mkdir(parents=True)
        config = self.root / 'config.json'
        config.write_text(json.dumps({'pier': str(pier), 'ship': '~zod',
            'recipient': self.recipient, 'output': str(self.root / 'snapshots')}))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(pier / '.urb/conn.sock'))
            for digest, unchanged, count in [('a', False, 1), ('a', True, 1), ('b', False, 1), ('b', True, 1)]:
                payload = json.dumps({'sha256': digest * 64, 'snapshot': digest}).encode()
                with patch.object(self.backup, 'capture', return_value=payload):
                    result = self.backup.scheduled(config)
                self.assertEqual(result['unchanged'], unchanged)
                self.assertEqual(result['localBackup'], 'latest.age')
                self.assertEqual(len(list((self.root / 'snapshots').glob('*.age'))), count)
                target = self.root / 'snapshots/latest.age'
                self.assertEqual(self.backup.unseal(target, self.key), payload)
                if unchanged:
                    self.assertEqual(target.read_bytes(), previous)
                previous = target.read_bytes()

    def schedule_fixture(self):
        import json
        import socket
        pier = self.root / 'pier'; (pier / '.urb').mkdir(parents=True)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(str(pier / '.urb/conn.sock'))
        output = self.root / 'snapshots'; output.mkdir(mode=0o700)
        config = self.root / 'config.json'
        config.write_text(json.dumps({'pier': str(pier), 'ship': '~zod',
            'recipient': self.recipient, 'output': str(output),
            'remote': 'test:backups', 'rcloneConfig': str(self.root / 'rclone.conf')}))
        return config, output

    def test_changed_offline_captures_retry_only_latest(self):
        import json
        from unittest.mock import patch
        config, output = self.schedule_fixture()
        for digest in ('a', 'b'):
            payload = json.dumps({'sha256': digest * 64, 'snapshot': digest}).encode()
            with patch.object(self.backup, 'capture', return_value=payload), \
                    patch.object(self.backup, 'upload', side_effect=RuntimeError('offline')):
                with self.assertRaises(RuntimeError): self.backup.scheduled(config)
        sent = []
        def send(target, remote, settings):
            sent.append(self.backup.unseal(target, self.key))
            return remote + '/' + target.name
        with patch.object(self.backup, 'capture', return_value=payload), \
                patch.object(self.backup, 'upload', side_effect=send):
            result = self.backup.scheduled(config)
        self.assertEqual(sent, [payload])
        self.assertEqual(result['uploaded'], 1)
        self.assertEqual([p.name for p in output.glob('*.age')], ['latest.age'])

    def test_failed_replacement_keeps_previous_archive_and_metadata(self):
        import json
        from unittest.mock import patch
        config, output = self.schedule_fixture()
        payload = json.dumps({'sha256': 'a' * 64, 'snapshot': 'a'}).encode()
        with patch.object(self.backup, 'capture', return_value=payload), \
                patch.object(self.backup, 'upload', side_effect=lambda target, remote, settings: remote + '/' + target.name):
            self.backup.scheduled(config)
        before = {p.name: p.read_bytes() for p in output.iterdir()}
        values = json.loads(config.read_text()); values['recipient'] = 'invalid'
        config.write_text(json.dumps(values))
        changed = json.dumps({'sha256': 'b' * 64, 'snapshot': 'b'}).encode()
        with patch.object(self.backup, 'capture', return_value=changed):
            with self.assertRaises(ValueError): self.backup.scheduled(config)
        self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, before)
        self.assertEqual(self.backup.unseal(output / 'latest.age', self.key), payload)

    def test_encryption_process_failure_preserves_latest(self):
        from unittest.mock import patch
        target = self.root / 'latest.age'
        self.backup.seal(b'previous verified capture', target, self.recipient)
        before = target.read_bytes()
        # A failing external age process can have written partial output already.
        commands = self.root / 'commands'; commands.mkdir()
        failed_age = commands / 'age'
        failed_age.write_text('#!/bin/sh\nprintf partial-encryption\nexit 7\n')
        failed_age.chmod(0o700)
        with patch.dict(os.environ, {'PATH': str(commands)}):
            with self.assertRaises(RuntimeError):
                self.backup.seal(b'new capture', target, self.recipient, replace=True)
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(self.backup.unseal(target, self.key), b'previous verified capture')
        self.assertEqual(list(self.root.glob('.vault-backup-*')), [])

    def test_scheduled_target_symlink_is_refused(self):
        import json
        from unittest.mock import patch
        config, output = self.schedule_fixture()
        unrelated = self.root / 'unrelated'; unrelated.write_bytes(b'preserve')
        (output / 'latest.age').symlink_to(unrelated)
        payload = json.dumps({'sha256': 'b' * 64, 'snapshot': 'b'}).encode()
        with patch.object(self.backup, 'capture', return_value=payload):
            with self.assertRaises(ValueError): self.backup.scheduled(config)
        self.assertEqual(unrelated.read_bytes(), b'preserve')
        self.assertTrue((output / 'latest.age').is_symlink())

    def test_replaces_managed_history_but_preserves_unrelated_files(self):
        import json
        from unittest.mock import patch
        config, output = self.schedule_fixture()
        old = output / ('20261019T091839Z-' + 'a' * 32 + '.age')
        self.backup.seal(b'old snapshot', old, self.recipient)
        old.with_suffix('.uploaded.json').write_text('{}')
        unrelated = output / 'manual.age'
        unrelated.write_bytes(b'unrelated user file')
        payload = json.dumps({'sha256': 'b' * 64, 'snapshot': 'b'}).encode()
        with patch.object(self.backup, 'capture', return_value=payload), \
                patch.object(self.backup, 'upload', side_effect=lambda target, remote, settings: remote + '/' + target.name):
            self.backup.scheduled(config)
        self.assertFalse(old.exists())
        self.assertFalse(old.with_suffix('.uploaded.json').exists())
        self.assertEqual(unrelated.read_bytes(), b'unrelated user file')
        self.assertEqual(self.backup.unseal(output / 'latest.age', self.key), payload)

    def test_failed_encryption_publishes_nothing(self):
        target = self.root / 'backup.age'
        with self.assertRaises((ValueError, RuntimeError)):
            self.backup.seal(b'synthetic snapshot', target, 'invalid-recipient')
        self.assertFalse(target.exists())
        self.assertEqual({p.name for p in self.root.iterdir()}, {'identity.txt'})

if __name__ == '__main__': unittest.main()
