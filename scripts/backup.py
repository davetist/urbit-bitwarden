"""Opaque full-pier backup and isolated restore; never starts or stops a ship."""
import argparse
import bz2
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import fcntl
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tempfile

from deploy import no_symlinks, runtime_binary, source_paths, validate_pier, validate_ship

MANIFEST = 'BITWARDEN-PIER-BACKUP.json'  # Existing archive format, retained for restore compatibility.
FORMAT = 'urbit-connect-stopped-pier-v1'
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_BYTES = 8 * 1024 ** 3
MAX_TAR_READ = 16 * 1024 ** 2


def digest_stream(stream, limit=None):
    digest = hashlib.sha256()
    total = 0
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        total += len(chunk)
        if limit is not None and total > limit: raise ValueError('Backup expanded byte limit exceeded')
        digest.update(chunk)
    return digest.hexdigest()


def check_limits(max_members, max_bytes):
    if not isinstance(max_members, int) or max_members < 1 or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError('Backup limits must be positive integers')


class LimitedTarReader:
    """Bound decompressed TAR reads, including headers hidden from iteration."""
    def __init__(self, stream, limit):
        self.stream = stream
        self.limit = limit

    def tell(self): return self.stream.tell()

    def seek(self, offset, whence=0):
        if whence == os.SEEK_SET: position = offset
        elif whence == os.SEEK_CUR: position = self.tell() + offset
        else: raise ValueError('Unsupported backup archive seek')
        if position < 0 or position > self.limit: raise ValueError('Backup expanded byte limit exceeded')
        return self.stream.seek(offset, whence)

    def read(self, size=-1):
        if size < 0 or self.tell() + size > self.limit:
            raise ValueError('Backup expanded byte limit exceeded')
        if size > MAX_TAR_READ: raise ValueError('Backup archive read limit exceeded')
        return self.stream.read(size)


@contextmanager
def open_backup_archive(path, max_members, max_bytes):
    check_limits(max_members, max_bytes)
    # TAR framing and optional PAX/GNU metadata need room beyond file payloads.
    # Even when those headers are consumed internally by tarfile, their total
    # decompressed extent stays within this finite reader budget.
    overhead = 512 * (4 * max_members + 2) + min(max_bytes, 4 * 1024 * 1024)
    with ExitStack() as stack:
        source = stack.enter_context(path.open('rb'))
        signature = source.read(6); source.seek(0)
        if signature.startswith(b'\x1f\x8b'): stream = stack.enter_context(gzip.GzipFile(fileobj=source))
        elif signature.startswith(b'BZh'): stream = stack.enter_context(bz2.BZ2File(source))
        elif signature.startswith(b'\xfd7zXZ\x00'): stream = stack.enter_context(lzma.LZMAFile(source))
        elif (signature.startswith(b'\x28\xb5\x2f\xfd') or
              signature[1:4] == b'\x2a\x4d\x18' and 0x50 <= signature[0] <= 0x5f):
            try: from compression.zstd import ZstdFile
            except ImportError: raise tarfile.CompressionError('Zstandard is unavailable') from None
            stream = stack.enter_context(ZstdFile(source, 'r'))
        else: stream = source
        archive = stack.enter_context(tarfile.open(fileobj=LimitedTarReader(stream, max_bytes + overhead), mode='r:'))
        yield archive


@contextmanager
def stopped_pier(pier):
    """Hold the same first-byte fcntl lock as stock Vere throughout the copy."""
    pier = validate_pier(pier)
    lock = no_symlinks(pier / '.vere.lock')
    existed = lock.exists()
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    acquired = False
    try:
        try: fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB, 1)
        except BlockingIOError: raise RuntimeError('Selected pier is running or locked; stop it normally before backup') from None
        acquired = True
        # Do not silently remove stale/ambiguous control endpoints.
        if (pier / '.urb/conn.sock').exists():
            raise RuntimeError('Selected pier still has a control socket; verify normal shutdown before backup')
        yield pier
    finally:
        # A pre-existing stale lock's content is preserved. A lock created here
        # is removed while held, just as Vere removes its own lock on shutdown.
        if acquired and not existed: lock.unlink()
        os.close(descriptor)


def source_entries(pier, max_members=MAX_ARCHIVE_MEMBERS, max_bytes=MAX_ARCHIVE_BYTES):
    check_limits(max_members, max_bytes)
    paths = []
    for path in source_paths(pier):
        relative = path.relative_to(pier).as_posix()
        if relative == '.vere.lock': continue
        paths.append(path)
        if len(paths) + 1 > max_members: raise ValueError('Backup member limit exceeded')
    entries = {}; total_bytes = 0
    for path in sorted(paths):
        relative = path.relative_to(pier).as_posix()
        if relative == '.run':
            path = runtime_binary(pier)
            info = path.stat()
        else:
            no_symlinks(path)
            info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            entries[relative] = {'kind': 'directory', 'mode': stat.S_IMODE(info.st_mode)}
        elif stat.S_ISREG(info.st_mode):
            total_bytes += info.st_size
            if total_bytes > max_bytes: raise ValueError('Backup expanded byte limit exceeded')
            with path.open('rb') as stream: digest = digest_stream(stream, info.st_size)
            entries[relative] = {'kind': 'file', 'mode': stat.S_IMODE(info.st_mode),
                                 'size': info.st_size, 'sha256': digest}
        else: raise ValueError('Pier contains a special file; preserve and inspect before backup: ' + relative)
    return entries


def create_backup(pier, output, ship, max_members=MAX_ARCHIVE_MEMBERS, max_bytes=MAX_ARCHIVE_BYTES):
    check_limits(max_members, max_bytes)
    pier = validate_pier(pier); output = no_symlinks(output); validate_ship(ship)
    if output.exists(): raise FileExistsError('Backup destination already exists')
    if output == pier or pier in output.parents: raise ValueError('Backup destination must be outside the pier')
    if not output.parent.is_dir(): raise ValueError('Backup destination parent must already exist')
    temporary = None
    with stopped_pier(pier):
        entries = source_entries(pier, max_members, max_bytes)
        manifest = {'format': FORMAT, 'ship': ship, 'createdAt': datetime.now(timezone.utc).isoformat(),
                    'sourcePier': str(pier), 'files': entries}
        raw = (json.dumps(manifest, indent=2) + '\n').encode()
        if len(raw) + sum(item.get('size', 0) for item in entries.values()) > max_bytes:
            raise ValueError('Backup expanded byte limit exceeded')
        descriptor, temporary = tempfile.mkstemp(prefix='.pier-backup-', suffix='.partial', dir=output.parent)
        os.close(descriptor)
        try:
            with tarfile.open(temporary, 'w:gz', dereference=True) as archive:
                info = tarfile.TarInfo(MANIFEST); info.size = len(raw); info.mode = 0o600
                archive.addfile(info, io.BytesIO(raw))
                for name, details in entries.items():
                    archive.add(pier / name, arcname='pier/' + name, recursive=False)
            # Verify byte integrity and every entry before publishing the archive.
            verify_backup(Path(temporary), max_members=max_members, max_bytes=max_bytes)
            if source_entries(pier, max_members, max_bytes) != entries:
                raise RuntimeError('Pier changed during backup; archive not published')
            os.link(temporary, output)  # Atomic publication, never overwrites.
            return manifest
        finally:
            if temporary is not None: Path(temporary).unlink(missing_ok=True)


def archive_members(archive, max_members=MAX_ARCHIVE_MEMBERS, max_bytes=MAX_ARCHIVE_BYTES):
    check_limits(max_members, max_bytes)
    by_name = {}; count = 0; expanded = 0
    for member in archive:
        count += 1
        if count > max_members: raise ValueError('Backup member limit exceeded')
        if member.size < 0: raise ValueError('Invalid archive member size')
        expanded += member.size
        if expanded > max_bytes: raise ValueError('Backup expanded byte limit exceeded')
        name = PurePosixPath(member.name)
        if (name.is_absolute() or '..' in name.parts or name.as_posix() != member.name or
                member.name in by_name or not (member.isfile() or member.isdir())):
            raise ValueError('Invalid archive member')
        by_name[member.name] = member
    if MANIFEST not in by_name or not by_name[MANIFEST].isfile() or by_name[MANIFEST].size > 16 * 1024 * 1024:
        raise ValueError('Backup manifest missing or oversized')
    manifest = json.load(archive.extractfile(by_name[MANIFEST]))
    if manifest.get('format') != FORMAT or not isinstance(manifest.get('files'), dict):
        raise ValueError('Unsupported backup format')
    validate_ship(manifest['ship'])
    expected = {MANIFEST} | {'pier/' + name for name in manifest['files']}
    if set(by_name) != expected: raise ValueError('Backup content differs from manifest')
    for name, details in manifest['files'].items():
        path = PurePosixPath(name)
        if (path.is_absolute() or '..' in path.parts or path.as_posix() != name or
                name in ('.vere.lock', '.urb/conn.sock') or not name):
            raise ValueError('Invalid manifest path')
        member = by_name['pier/' + name]
        if (details.get('kind') == 'directory') != member.isdir(): raise ValueError('Backup entry kind mismatch')
        if details.get('kind') not in ('directory', 'file'): raise ValueError('Invalid backup entry kind')
        if details.get('mode') != member.mode or member.mode & ~0o777:
            raise ValueError('Backup file mode mismatch')
        # A manifest cannot place files underneath an entry that is itself a file.
        for parent in path.parents:
            if parent == PurePosixPath('.'): continue
            if manifest['files'].get(str(parent), {}).get('kind') != 'directory':
                raise ValueError('Backup parent directory missing')
        if member.isfile():
            if member.size != details.get('size'): raise ValueError('Backup size mismatch')
    # Read payloads in archive order. A hostile manifest order must not force
    # repeated rewinds and decompression of the same large compressed archive.
    for member_name, member in by_name.items():
        if member_name == MANIFEST or not member.isfile(): continue
        details = manifest['files'][member_name[len('pier/'):]]
        with archive.extractfile(member) as stream: digest = digest_stream(stream, member.size)
        if digest != details.get('sha256'): raise ValueError('Backup hash mismatch')
    if (manifest['files'].get('.urb', {}).get('kind') != 'directory' or
            manifest['files'].get('.run', {}).get('kind') != 'file'):
        raise ValueError('Backup does not contain a docked pier')
    return manifest, by_name, expanded


def verify_backup(path, max_members=MAX_ARCHIVE_MEMBERS, max_bytes=MAX_ARCHIVE_BYTES):
    path = no_symlinks(path)
    with open_backup_archive(path, max_members, max_bytes) as archive:
        manifest, _, _ = archive_members(archive, max_members, max_bytes)
        return manifest


def restore_backup(archive_path, target, max_members=MAX_ARCHIVE_MEMBERS, max_bytes=MAX_ARCHIVE_BYTES):
    archive_path = no_symlinks(archive_path); target = no_symlinks(target)
    if target.exists(): raise FileExistsError('Restore target must be a new, absent directory')
    if not target.parent.is_dir(): raise ValueError('Restore target parent must already exist')
    # Validate everything before creating the target; only a private sibling
    # staging directory exists during extraction. No source pier is changed.
    with open_backup_archive(archive_path, max_members, max_bytes) as archive:
        manifest, members, expanded = archive_members(archive, max_members, max_bytes)
        if expanded > shutil.disk_usage(target.parent).free:
            raise ValueError('Not enough free space for backup restore')
        staging = Path(tempfile.mkdtemp(prefix='.pier-restore-', dir=target.parent))
        try:
            for name, details in sorted(manifest['files'].items(), key=lambda pair: (len(PurePosixPath(pair[0]).parts), pair[0])):
                if details['kind'] == 'directory': (staging / name).mkdir(mode=0o700)
            for member_name, member in members.items():
                if member_name == MANIFEST or not member.isfile(): continue
                name = member_name[len('pier/'):]; details = manifest['files'][name]
                path = staging / name
                with archive.extractfile(member) as source, path.open('xb') as destination:
                    remaining = details['size']
                    while remaining:
                        chunk = source.read(min(1024 * 1024, remaining))
                        if not chunk: raise ValueError('Backup size mismatch during restore')
                        destination.write(chunk); remaining -= len(chunk)
                    if source.read(1): raise ValueError('Backup size mismatch during restore')
                path.chmod(details['mode'])
            for name, details in manifest['files'].items():
                if details['kind'] == 'directory': (staging / name).chmod(details['mode'])
            if source_entries(staging, max_members, max_bytes) != manifest['files']:
                raise ValueError('Restored file hash verification failed')
            # Reserve target without replacing an existing path, then move only
            # into the directory that this operation just created.
            target.mkdir(mode=0o700)
            try:
                for path in staging.iterdir(): path.rename(target / path.name)
            except BaseException:
                # Preserve any partial restored data for inspection, never erase
                # an unexpected external target or launch it automatically.
                raise RuntimeError('Restore publication interrupted; target remains stopped for inspection') from None
            return manifest
        finally: shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    def add_limits(command):
        def positive(value):
            number = int(value)
            if number < 1: raise argparse.ArgumentTypeError('Limit must be positive')
            return number
        command.add_argument('--max-members', type=positive, default=MAX_ARCHIVE_MEMBERS)
        command.add_argument('--max-expanded-gib', type=positive, default=8)
    create = commands.add_parser('create'); create.add_argument('--pier', required=True, type=Path)
    create.add_argument('--ship', required=True); create.add_argument('--output', required=True, type=Path)
    add_limits(create)
    verify = commands.add_parser('verify'); verify.add_argument('--archive', required=True, type=Path)
    add_limits(verify)
    restore = commands.add_parser('restore'); restore.add_argument('--archive', required=True, type=Path)
    restore.add_argument('--target', required=True, type=Path)
    add_limits(restore)
    args = parser.parse_args()
    try:
        limits = {'max_members': args.max_members, 'max_bytes': args.max_expanded_gib * 1024 ** 3}
        if args.command == 'create': manifest = create_backup(args.pier, args.output, args.ship, **limits)
        elif args.command == 'verify': manifest = verify_backup(args.archive, **limits)
        else: manifest = restore_backup(args.archive, args.target, **limits)
        print(json.dumps({'operation': args.command, 'ship': manifest['ship'],
                          'filesVerified': sum(v['kind'] == 'file' for v in manifest['files'].values()),
                          'createdAt': manifest['createdAt'], 'shipStarted': False}, indent=2))
        if args.command == 'restore':
            print('Restored but stopped. Never run two copies of one networked ship; use the recovery procedure before booting.')
    except (OSError, ValueError, RuntimeError, tarfile.TarError) as error:
        raise SystemExit(str(error)) from None


if __name__ == '__main__': main()
