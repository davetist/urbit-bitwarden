"""Opaque stopped-pier archive/restore checks using synthetic filesystem data."""
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import backup


class BackupTests(unittest.TestCase):
    def pier(self, root):
        pier = root / 'source'; (pier / '.urb/log').mkdir(parents=True)
        (pier / '.urb/chk').mkdir(); (pier / '.urb/log/opaque').write_bytes(b'ciphertext and opaque events')
        (pier / '.urb/chk/snapshot').write_bytes(b'wrapped keys and opaque state')
        (pier / '.run').write_bytes(b'fake executable'); (pier / '.run').chmod(0o700)
        return pier

    def test_roundtrip_preserves_files_modes_and_never_starts_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); pier = self.pier(root); archive = root / 'backup.tgz'
            manifest = backup.create_backup(pier, archive, '~sampel-palnet')
            self.assertEqual(manifest['ship'], '~sampel-palnet')
            self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
            self.assertFalse((pier / '.vere.lock').exists())
            target = root / 'restored'
            backup.restore_backup(archive, target)
            for path in pier.rglob('*'):
                if path.is_file(): self.assertEqual(path.read_bytes(), (target / path.relative_to(pier)).read_bytes())
            self.assertEqual((target / '.run').stat().st_mode & 0o777, 0o700)
            self.assertFalse((target / '.urb/conn.sock').exists())
            self.assertFalse((target / '.vere.lock').exists())

    def test_runtime_symlink_is_materialized_for_relocated_restore(self):
        for external in (False, True):
            with self.subTest(external=external), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(); pier = self.pier(root)
                runtime = root / 'runtime' if external else pier / '.bin/live/vere'
                runtime.parent.mkdir(parents=True, exist_ok=True)
                runtime.write_bytes(b'opaque selected runtime executable'); runtime.chmod(0o755)
                (pier / '.run').unlink()
                (pier / '.run').symlink_to(runtime if external else '.bin/live/vere')
                archive = root / 'backup.tgz'
                backup.create_backup(pier, archive, '~zod')
                target = root / 'restored'; backup.restore_backup(archive, target)
                self.assertTrue((pier / '.run').is_symlink())
                self.assertFalse((target / '.run').is_symlink())
                self.assertEqual((target / '.run').read_bytes(), runtime.read_bytes())
                self.assertEqual((target / '.run').stat().st_mode & 0o777, 0o755)
                self.assertFalse((target / '.urb/conn.sock').exists())

    def test_live_vere_lock_is_refused_and_existing_file_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); pier = self.pier(root)
            lock = pier / '.vere.lock'; lock.write_text('12345\n')
            child = subprocess.Popen([sys.executable, '-c',
                "import fcntl,sys; f=open(sys.argv[1],'r+'); fcntl.lockf(f,fcntl.LOCK_EX,1); print('ready',flush=True); sys.stdin.read()",
                str(lock)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(), 'ready')
                with self.assertRaisesRegex(RuntimeError, 'running|locked'):
                    backup.create_backup(pier, root / 'backup.tgz', '~sampel-palnet')
            finally: child.communicate(timeout=5)
            self.assertEqual(lock.read_text(), '12345\n')
            self.assertFalse((root / 'backup.tgz').exists())

    def test_lock_blocks_concurrent_runtime_style_acquisition(self):
        with tempfile.TemporaryDirectory() as directory:
            pier = self.pier(Path(directory).resolve())
            with backup.stopped_pier(pier):
                result = subprocess.run([sys.executable, '-c',
                    "import fcntl,sys; f=open(sys.argv[1],'r+'); fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB,1)",
                    str(pier / '.vere.lock')], capture_output=True)
                self.assertNotEqual(result.returncode, 0)

    def test_source_links_and_overwrite_targets_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); pier = self.pier(root); archive = root / 'backup.tgz'
            (pier / 'link').symlink_to(root)
            with self.assertRaisesRegex(ValueError, 'symlink'): backup.create_backup(pier, archive, '~zod')
            self.assertFalse(archive.exists()); (pier / 'link').unlink()
            backup.create_backup(pier, archive, '~zod')
            original = archive.read_bytes()
            with self.assertRaises(FileExistsError): backup.create_backup(pier, archive, '~zod')
            self.assertEqual(archive.read_bytes(), original)
            target = root / 'already-there'; target.mkdir(); (target / 'keep').write_text('preserved')
            with self.assertRaises(FileExistsError): backup.restore_backup(archive, target)
            self.assertEqual((target / 'keep').read_text(), 'preserved')

    def test_corrupt_archive_is_refused_without_partial_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); pier = self.pier(root); archive = root / 'backup.tgz'
            backup.create_backup(pier, archive, '~zod')
            bad = root / 'corrupt.tgz'
            with tarfile.open(archive) as source, tarfile.open(bad, 'w:gz') as dest:
                for item in source:
                    raw = source.extractfile(item).read() if item.isfile() else None
                    if item.name == 'pier/.urb/chk/snapshot': raw = b'changed'; item.size = len(raw)
                    dest.addfile(item, io.BytesIO(raw) if raw is not None else None)
            target = root / 'restored'
            with self.assertRaisesRegex(ValueError, 'hash|size'): backup.restore_backup(bad, target)
            self.assertFalse(target.exists())

    def test_archive_member_and_expanded_byte_limits_precede_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); pier = self.pier(root); archive = root / 'backup.tgz'
            backup.create_backup(pier, archive, '~zod')
            for limits, message in [({'max_members': 3}, 'member limit'),
                                    ({'max_bytes': 64}, 'expanded byte limit')]:
                with self.subTest(limits=limits):
                    target = root / 'restored'
                    with self.assertRaisesRegex(ValueError, message):
                        backup.verify_backup(archive, **limits)
                    with self.assertRaisesRegex(ValueError, message):
                        backup.restore_backup(archive, target, **limits)
                    self.assertFalse(target.exists())
            with self.assertRaisesRegex(ValueError, 'member limit'):
                backup.create_backup(pier, root / 'too-small.tgz', '~zod', max_members=3)
            self.assertFalse((root / 'too-small.tgz').exists())

    def test_restore_refuses_archive_larger_than_free_space(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); pier = self.pier(root); archive = root / 'backup.tgz'
            backup.create_backup(pier, archive, '~zod')
            target = root / 'restored'
            with patch('backup.shutil.disk_usage', return_value=SimpleNamespace(free=1)):
                with self.assertRaisesRegex(ValueError, 'free space'):
                    backup.restore_backup(archive, target)
            self.assertFalse(target.exists())

    def test_hidden_pax_metadata_cannot_bypass_expanded_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); pier = self.pier(root); archive = root / 'backup.tgz'
            backup.create_backup(pier, archive, '~zod')
            decorated = root / 'pax.tgz'
            with tarfile.open(archive) as source, tarfile.open(
                    decorated, 'w:gz', pax_headers={'comment': 'x' * 100_000}) as destination:
                for item in source:
                    raw = source.extractfile(item).read() if item.isfile() else None
                    destination.addfile(item, io.BytesIO(raw) if raw is not None else None)
            with tarfile.open(archive) as source:
                payload = sum(item.size for item in source)
                members = len(source.getmembers())
            with self.assertRaisesRegex(ValueError, 'expanded byte limit'):
                backup.verify_backup(decorated, max_members=members, max_bytes=payload)
            target = root / 'restored'
            with self.assertRaisesRegex(ValueError, 'expanded byte limit'):
                backup.restore_backup(decorated, target, max_members=members, max_bytes=payload)
            self.assertFalse(target.exists())
            with patch.object(backup, 'MAX_TAR_READ', 4096):
                with self.assertRaisesRegex(ValueError, 'archive read limit'):
                    backup.verify_backup(decorated)

    def test_existing_tar_compression_formats_still_verify(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); pier = self.pier(root); archive = root / 'backup.tgz'
            backup.create_backup(pier, archive, '~zod')
            formats = [('w:', '.tar'), ('w:bz2', '.tar.bz2'), ('w:xz', '.tar.xz')]
            if 'zst' in tarfile.TarFile.OPEN_METH: formats.append(('w:zst', '.tar.zst'))
            for mode, suffix in formats:
                with self.subTest(mode=mode):
                    repacked = root / ('backup' + suffix)
                    with tarfile.open(archive) as source, tarfile.open(repacked, mode) as destination:
                        for item in source:
                            raw = source.extractfile(item).read() if item.isfile() else None
                            destination.addfile(item, io.BytesIO(raw) if raw is not None else None)
                    self.assertEqual(backup.verify_backup(repacked)['ship'], '~zod')

    def test_destination_must_be_outside_source(self):
        with tempfile.TemporaryDirectory() as directory:
            pier = self.pier(Path(directory).resolve())
            with self.assertRaisesRegex(ValueError, 'outside'): backup.create_backup(pier, pier / 'backup.tgz', '~zod')


if __name__ == '__main__': unittest.main()
