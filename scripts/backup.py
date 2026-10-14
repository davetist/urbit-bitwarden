"""Opaque full-pier backup and isolated restore; never starts or stops a ship."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tempfile

from deploy import no_symlinks, runtime_binary, validate_pier, validate_ship

MANIFEST = 'BITWARDEN-PIER-BACKUP.json'
FORMAT = 'urbit-connect-stopped-pier-v1'


def digest_stream(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b''): digest.update(chunk)
    return digest.hexdigest()


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


def source_entries(pier):
    entries = {}
    for path in sorted(pier.rglob('*')):
        relative = path.relative_to(pier).as_posix()
        if relative == '.vere.lock': continue
        if relative == '.run':
            path = runtime_binary(pier)
            info = path.stat()
        else:
            no_symlinks(path)
            info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            entries[relative] = {'kind': 'directory', 'mode': stat.S_IMODE(info.st_mode)}
        elif stat.S_ISREG(info.st_mode):
            with path.open('rb') as stream: digest = digest_stream(stream)
            entries[relative] = {'kind': 'file', 'mode': stat.S_IMODE(info.st_mode),
                                 'size': info.st_size, 'sha256': digest}
        else: raise ValueError('Pier contains a special file; preserve and inspect before backup: ' + relative)
    return entries


def create_backup(pier, output, ship):
    pier = validate_pier(pier); output = no_symlinks(output); validate_ship(ship)
    if output.exists(): raise FileExistsError('Backup destination already exists')
    if output == pier or pier in output.parents: raise ValueError('Backup destination must be outside the pier')
    if not output.parent.is_dir(): raise ValueError('Backup destination parent must already exist')
    temporary = None
    with stopped_pier(pier):
        entries = source_entries(pier)
        manifest = {'format': FORMAT, 'ship': ship, 'createdAt': datetime.now(timezone.utc).isoformat(),
                    'sourcePier': str(pier), 'files': entries}
        descriptor, temporary = tempfile.mkstemp(prefix='.pier-backup-', suffix='.partial', dir=output.parent)
        os.close(descriptor)
        try:
            with tarfile.open(temporary, 'w:gz', dereference=True) as archive:
                raw = (json.dumps(manifest, indent=2) + '\n').encode()
                info = tarfile.TarInfo(MANIFEST); info.size = len(raw); info.mode = 0o600
                archive.addfile(info, io.BytesIO(raw))
                for name, details in entries.items():
                    archive.add(pier / name, arcname='pier/' + name, recursive=False)
            # Verify byte integrity and every entry before publishing the archive.
            verify_backup(Path(temporary))
            if source_entries(pier) != entries: raise RuntimeError('Pier changed during backup; archive not published')
            os.link(temporary, output)  # Atomic publication, never overwrites.
            return manifest
        finally:
            if temporary is not None: Path(temporary).unlink(missing_ok=True)


def archive_members(archive):
    members = archive.getmembers(); by_name = {}
    for member in members:
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
            with archive.extractfile(member) as stream: digest = digest_stream(stream)
            if digest != details.get('sha256'): raise ValueError('Backup hash mismatch')
    if (manifest['files'].get('.urb', {}).get('kind') != 'directory' or
            manifest['files'].get('.run', {}).get('kind') != 'file'):
        raise ValueError('Backup does not contain a docked pier')
    return manifest, by_name


def verify_backup(path):
    path = no_symlinks(path)
    with tarfile.open(path, 'r:*') as archive:
        manifest, _ = archive_members(archive)
        return manifest


def restore_backup(archive_path, target):
    archive_path = no_symlinks(archive_path); target = no_symlinks(target)
    if target.exists(): raise FileExistsError('Restore target must be a new, absent directory')
    if not target.parent.is_dir(): raise ValueError('Restore target parent must already exist')
    # Validate everything before creating the target; only a private sibling
    # staging directory exists during extraction. No source pier is changed.
    with tarfile.open(archive_path, 'r:*') as archive:
        manifest, members = archive_members(archive)
        staging = Path(tempfile.mkdtemp(prefix='.pier-restore-', dir=target.parent))
        try:
            for name, details in sorted(manifest['files'].items(), key=lambda pair: (len(PurePosixPath(pair[0]).parts), pair[0])):
                path = staging / name
                if details['kind'] == 'directory': path.mkdir(mode=0o700)
                else:
                    with archive.extractfile(members['pier/' + name]) as source, path.open('xb') as destination:
                        shutil.copyfileobj(source, destination, 1024 * 1024)
                    path.chmod(details['mode'])
            for name, details in manifest['files'].items():
                if details['kind'] == 'directory': (staging / name).chmod(details['mode'])
            if source_entries(staging) != manifest['files']: raise ValueError('Restored file hash verification failed')
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
    create = commands.add_parser('create'); create.add_argument('--pier', required=True, type=Path)
    create.add_argument('--ship', required=True); create.add_argument('--output', required=True, type=Path)
    verify = commands.add_parser('verify'); verify.add_argument('--archive', required=True, type=Path)
    restore = commands.add_parser('restore'); restore.add_argument('--archive', required=True, type=Path)
    restore.add_argument('--target', required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'create': manifest = create_backup(args.pier, args.output, args.ship)
        elif args.command == 'verify': manifest = verify_backup(args.archive)
        else: manifest = restore_backup(args.archive, args.target)
        print(json.dumps({'operation': args.command, 'ship': manifest['ship'],
                          'filesVerified': sum(v['kind'] == 'file' for v in manifest['files'].values()),
                          'createdAt': manifest['createdAt'], 'shipStarted': False}, indent=2))
        if args.command == 'restore':
            print('Restored but stopped. Never run two copies of one networked ship; use the recovery procedure before booting.')
    except (OSError, ValueError, RuntimeError, tarfile.TarError) as error:
        raise SystemExit(str(error)) from None


if __name__ == '__main__': main()
