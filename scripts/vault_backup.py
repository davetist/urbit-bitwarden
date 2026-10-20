"""Live, age-encrypted Urbitwarden snapshots; no vault password is needed.

Only account/key metadata and encrypted content are captured. Ship networking,
Connect grants, sessions, signing keys and HTTP credentials are never restored.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import deploy
from compile_desk import source_cord

FORMAT = 'urbitwarden-vault-backup-v1'


def prefix(ship):
    deploy.validate_ship(ship)
    return ('=/  m  (strand ,vase)  ;<  our=@p  bind:m  get-our  '
            f'?>  =(our {ship})  ;<  now=@da  bind:m  get-time  ')


def capture(control, ship):
    deploy.validate_ship(ship)
    result = control.peek('urbitwarden', ['backup', 'noun'], max_reply_bytes=None)
    # conn's direct scry does not close a pending large reply like the 4.6
    # thread-response path on macOS. No intermediate state file is needed.
    for expected in (0, int.from_bytes(b'peek', 'little'), 0, int.from_bytes(b'omen', 'little')):
        if not isinstance(result, tuple) or result[0] != expected:
            raise RuntimeError('Vault snapshot endpoint unavailable; update the selected desk')
        result = result[1]
    if not isinstance(result, tuple): raise ValueError('Malformed snapshot location')
    result = result[1]
    if not isinstance(result, tuple) or result[0] != int.from_bytes(b'noun', 'little'):
        raise ValueError('Unexpected snapshot mark')
    result = result[1]
    if not isinstance(result, tuple): raise ValueError('Malformed vault snapshot')
    identity, value = result
    if deploy.cord(identity) != ship: raise ValueError('Selected ship identity does not match snapshot')
    if not isinstance(value, int) or value <= 0:
        raise ValueError('The selected vault did not return a snapshot')
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'little')
    return json.dumps({'format': FORMAT, 'sourceShip': ship,
        'createdAt': datetime.now(timezone.utc).isoformat(),
        'sha256': hashlib.sha256(raw).hexdigest(),
        'snapshot': base64.b64encode(raw).decode()}, separators=(',', ':')).encode()


def private_directory(path):
    path = Path(path).expanduser().absolute()
    deploy.no_symlinks(path)
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError('Backup directory must be owned by this user and mode 0700')
    return path


def seal(payload, target, recipient, *, replace=False):
    target = Path(target).absolute()
    deploy.no_symlinks(target)
    if target.exists() and not replace: raise FileExistsError('Backup already exists')
    if not re.fullmatch(r'age1[0-9a-z]+', recipient):
        raise ValueError('Use an age X25519 public recipient')
    descriptor, temporary = tempfile.mkstemp(prefix='.vault-backup-', dir=target.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            result = subprocess.run(['age', '--encrypt', '--recipient', recipient],
                input=payload, stdout=stream, stderr=subprocess.PIPE, check=False)
            if result.returncode: raise RuntimeError('age encryption failed; no backup published')
            stream.flush(); os.fsync(stream.fileno())
        # Scheduled replacement keeps the old archive until encryption is durable.
        # Manual capture still refuses an existing destination.
        if replace: os.replace(temporary, target)
        else: os.link(temporary, target)
        directory = os.open(target.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def unseal(target, identity):
    identity = deploy.no_symlinks(Path(identity).absolute())
    if identity.stat().st_mode & 0o077:
        raise ValueError('Recovery identity must have private permissions')
    result = subprocess.run(['age', '--decrypt', '--identity', str(identity), str(target)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode: raise RuntimeError('Backup decryption or authentication failed')
    return result.stdout


def decode(payload):
    value = json.loads(payload)
    if not isinstance(value, dict) or value.get('format') != FORMAT:
        raise ValueError('Unsupported vault backup format')
    raw = base64.b64decode(value['snapshot'], validate=True)
    if not raw or hashlib.sha256(raw).hexdigest() != value.get('sha256'):
        raise ValueError('Snapshot checksum mismatch')
    # Verify the typed envelope in Python before sending anything to the target.
    noun = deploy.cue(raw)
    if not isinstance(noun, tuple) or noun[0] != int.from_bytes(b'urbitwarden-backup', 'little'):
        raise ValueError('Invalid snapshot tag')
    if not isinstance(noun[1], tuple) or noun[1][0] != 1:
        raise ValueError('Unsupported snapshot version')
    return raw


def restore(control, ship, origin, payload, apply=False):
    origin = deploy.validate_origin(origin)
    raw = decode(payload)
    # Check before dispatch; the receiver checks again in the atomic restore event.
    check = prefix(ship) + (
        '=/  egg  .^(egg-any:gall %gv /(scot %p our)/urbitwarden/(scot %da now)/(scot %tas %$))  '
        '?>  ?=([%20 %live *] egg)  =/  saved  +.old-state.egg  '
        "(pure:m !>(q:(slap (slop saved !>(.)) (ream '&(=(account ~) =(ciphers ~) =(folders ~) =(attachments ~))'))))")
    if control.run(check) != 0:
        raise ValueError('Restore requires an unenrolled, empty destination vault')
    if not apply: return {'destinationEmpty': True, 'applied': False}
    data = source_cord(raw)
    origin_literal = source_cord(origin.encode())
    expression = prefix(ship) + (
        f'=/  snapshot  (cue {data})  '
        f';<  ~  bind:m  (poke-our %urbitwarden %urbitwarden-restore !>([{origin_literal} snapshot]))  '
        '(pure:m !>(~))')
    control.run(expression)
    # Compare all restored ciphertext, folders, attachments and sequence counter.
    expression = prefix(ship) + (
        '=/  egg  .^(egg-any:gall %gv /(scot %p our)/urbitwarden/(scot %da now)/(scot %tas %$))  '
        '?>  ?=([%20 %live *] egg)  =/  saved  +.old-state.egg  '
        "(pure:m !>(q:(slap (slop saved !>(.)) (ream '(shax (jam [ciphers folders attachments serial]))'))))")
    # Compute expected field digest with the same typed native snapshot shape.
    expected = prefix(ship) + f'=/  [tag=@tas version=@ud account=* ciphers=* folders=* attachments=* serial=@ud revision=@da]  ;;([@tas @ud * * * * @ud @da] (cue {data}))  (pure:m !>((shax (jam [ciphers folders attachments serial]))))'
    if control.run(expression) != control.run(expected):
        raise RuntimeError('Restored content verification failed; preserve destination for inspection')
    return {'destinationEmpty': True, 'applied': True, 'contentVerified': True,
            'freshAuthorizationRequired': True}


def upload(target, remote, rclone_config):
    if not re.fullmatch(r'[A-Za-z0-9_-]+:[^\\\r\n]*', remote):
        raise ValueError('Use a configured rclone remote and backup folder')
    destination = remote.rstrip('/') + '/' + target.name
    args = ['rclone', '--config', str(rclone_config)]
    # Replace this one key, then download and hash readback before recording success.
    result = subprocess.run(args + ['copyto', str(target), destination, '--checksum'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode: raise RuntimeError('Encrypted cloud upload failed')
    result = subprocess.run(args + ['cat', destination], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False)
    if result.returncode or hashlib.sha256(result.stdout).digest() != hashlib.sha256(target.read_bytes()).digest():
        raise RuntimeError('Cloud backup readback failed')
    return destination


def write_private_json(path, value):
    deploy.no_symlinks(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def scheduled(config_path):
    config_path = deploy.no_symlinks(Path(config_path).absolute())
    config = json.loads(config_path.read_text())
    output = private_directory(config['output'])
    lock = output / '.backup.lock'
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        payload = capture(deploy.Control(config['pier'], require_runtime=False), config['ship'])
        snapshot_digest = json.loads(payload)['sha256']
        status_path = output / 'status.json'
        latest_path = output / 'latest.json'
        previous_path = latest_path if latest_path.exists() else status_path
        previous = json.loads(previous_path.read_text()) if previous_path.exists() else {}
        target = deploy.no_symlinks(output / 'latest.age')
        reusable = (previous.get('localBackup') == target.name and target.is_file() and
            snapshot_digest == previous.get('snapshotSHA256') and
            hashlib.sha256(target.read_bytes()).hexdigest() == previous.get('archiveSHA256'))
        if not reusable:
            seal(payload, target, config['recipient'], replace=True)
        # Record capture before upload: an offline retry must reuse unchanged data.
        latest = {'localBackup': target.name, 'snapshotSHA256': snapshot_digest,
                  'archiveSHA256': hashlib.sha256(target.read_bytes()).hexdigest()}
        write_private_json(latest_path, latest)
        # Remove only archives named by the previous scheduler, after latest is safe.
        # Cloud history must be cleared once by the storage administrator; the Pi
        # keeps its upload/read-only credential. S3 versioning must be suspended.
        obsolete = []
        for legacy in output.iterdir():
            if re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}\.age', legacy.name):
                for path in (legacy, legacy.with_suffix('.uploaded.json')):
                    deploy.no_symlinks(path)
                    if path.exists():
                        if not path.is_file(): raise ValueError('Legacy backup is not a regular file')
                        obsolete.append(path)
        for path in obsolete: path.unlink()
        if obsolete:
            directory = os.open(output, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
        # An offline run retries only the current latest capture. A newer capture
        # supersedes pending old ciphertext; receipts bind destination and bytes.
        uploaded = 0
        if config.get('remote'):
            receipt = deploy.no_symlinks(target.with_suffix('.uploaded.json'))
            expected = {'key': config['remote'].rstrip('/') + '/' + target.name,
                        'sha256': latest['archiveSHA256']}
            if not receipt.exists() or json.loads(receipt.read_text()) != expected:
                key = upload(target, config['remote'], config['rcloneConfig'])
                write_private_json(receipt, {'key': key, 'sha256': latest['archiveSHA256']})
                uploaded = 1
        status = {'lastSuccess': datetime.now(timezone.utc).isoformat(), 'localBackup': target.name,
                  'cloudConfigured': bool(config.get('remote')), 'uploaded': uploaded,
                  'snapshotSHA256': snapshot_digest, 'archiveSHA256': hashlib.sha256(target.read_bytes()).hexdigest(),
                  'unchanged': bool(reusable)}
        write_private_json(status_path, status)
        return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('create')
    create.add_argument('--pier', required=True, type=Path); create.add_argument('--ship', required=True)
    create.add_argument('--recipient', required=True); create.add_argument('--output', required=True, type=Path)
    recover = commands.add_parser('restore')
    recover.add_argument('--pier', required=True, type=Path); recover.add_argument('--ship', required=True)
    recover.add_argument('--origin', required=True); recover.add_argument('--identity', required=True, type=Path)
    recover.add_argument('--archive', required=True, type=Path); recover.add_argument('--apply', action='store_true')
    verify = commands.add_parser('verify')
    verify.add_argument('--identity', required=True, type=Path); verify.add_argument('--archive', required=True, type=Path)
    run = commands.add_parser('run'); run.add_argument('--config', required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'create':
        private_directory(args.output.parent)
        seal(capture(deploy.Control(args.pier, require_runtime=False), args.ship), args.output, args.recipient)
        print('Encrypted vault snapshot created; ship remains running.')
    elif args.command == 'restore':
        print(json.dumps(restore(deploy.Control(args.pier, require_runtime=False), args.ship, args.origin,
            unseal(args.archive, args.identity), args.apply)))
    elif args.command == 'verify':
        decode(unseal(args.archive, args.identity)); print('Backup decrypted and snapshot integrity verified.')
    else:
        print(json.dumps(scheduled(args.config)))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        # Never print arbitrary native payloads, SDK messages, or credentials.
        detail = str(error) if type(error) in (ValueError, RuntimeError, FileExistsError) else type(error).__name__
        print('Vault backup operation failed: ' + detail + '. No success was recorded.', file=__import__('sys').stderr)
        raise SystemExit(1)
