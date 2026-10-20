"""Private state and diagnostics. Never include vault values in errors."""
import base64
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path


class MigrationError(Exception):
    """An actionable, credential-free error safe to show in a terminal."""


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def file_digest(path):
    result = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''): result.update(chunk)
    return result.hexdigest()


def strict_json(data):
    def pairs(values):
        result={}
        for key,value in values:
            if key in result: raise MigrationError('Duplicate JSON keys are ambiguous and cannot be migrated.')
            result[key]=value
        return result
    def constant(_): raise MigrationError('Non-finite JSON numbers are unsupported.')
    return json.loads(data,object_pairs_hook=pairs,parse_constant=constant)


def private_directory(path, create=False):
    path = Path(path).absolute()
    if path.is_symlink(): raise MigrationError('Private directory cannot be a symlink.')
    if create: path.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise MigrationError('Work directory must be owned by you and have mode 0700.')
    return path.resolve()


def read_json(path):
    path = Path(path)
    if path.is_symlink(): raise MigrationError('State files cannot be symlinks.')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise MigrationError('State files must be owned by you and have mode 0600.')
    try: return strict_json(path.read_bytes())
    except (ValueError, UnicodeError): raise MigrationError('Invalid JSON in private state/review file.') from None


def write_json(path, value):
    path = Path(path)
    if path.is_symlink(): raise MigrationError('Refusing to overwrite a symlink.')
    fd, temporary = tempfile.mkstemp(prefix='.writing-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(value) + b'\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def decode64(value):
    if not isinstance(value, str) or not value: raise MigrationError('Missing passkey key material.')
    try: return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    except (ValueError, TypeError): raise MigrationError('Malformed passkey encoding.') from None


def credential_id(value):
    import uuid
    if not isinstance(value, str): raise MigrationError('Missing passkey credential ID.')
    if value.startswith('b64.'):
        return base64.urlsafe_b64encode(decode64(value[4:])).decode().rstrip('=')
    try: return base64.urlsafe_b64encode(uuid.UUID(value).bytes).decode().rstrip('=')
    except ValueError:
        return base64.urlsafe_b64encode(decode64(value)).decode().rstrip('=')


def passkey_fingerprint(key):
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    from cryptography.hazmat.primitives.asymmetric import ec
    raw = decode64(key.get('keyValue'))
    try: private=load_der_private_key(raw, password=None)
    except (ValueError, TypeError): raise MigrationError('Passkey does not contain a valid private key.') from None
    required = ('rpId', 'userHandle', 'keyType', 'keyAlgorithm', 'keyCurve')
    if any(not isinstance(key.get(k), str) or not key[k] for k in required):
        raise MigrationError('Incomplete passkey metadata.')
    if (key['keyType']!='public-key' or key['keyAlgorithm']!='ECDSA' or key['keyCurve']!='P-256'
            or not isinstance(private,ec.EllipticCurvePrivateKey) or not isinstance(private.curve,ec.SECP256R1)):
        raise MigrationError('Passkey algorithm is not supported by the inspected Bitwarden CXP contract.')
    values = {k: key.get(k) for k in ('rpId', 'keyType', 'keyAlgorithm', 'keyCurve',
                                    'userName', 'userDisplayName', 'discoverable')}
    values.update(credentialId=credential_id(key.get('credentialId')),
                  keySha256=digest(raw), userHandle=digest(decode64(key['userHandle'])))
    return digest(values)


MARKER = 'urbitwarden.1password.source'


def item_projection(item):
    """Stable native content; counters, server timestamps and download URLs are not content."""
    import copy
    keys = ('type', 'name', 'notes', 'favorite', 'reprompt', 'folderId', 'fields',
            'login', 'card', 'identity', 'sshKey', 'secureNote', 'passwordHistory')
    result = {k: copy.deepcopy(item.get(k)) for k in keys}
    result['notes'] = result['notes'] or ''
    result['favorite'] = bool(result['favorite'])
    result['reprompt'] = result['reprompt'] or 0
    result['fields'] = [{k: f.get(k) for k in ('name', 'value', 'type', 'linkedId')}
                        for f in result['fields'] or []]
    result['passwordHistory'] = result['passwordHistory'] or []
    if result['login'] is not None:
        login = result['login']
        result['login'] = {k: login.get(k) for k in ('username', 'password', 'totp')}
        result['login']['uris'] = [{k: u.get(k) for k in ('uri', 'match')} for u in login.get('uris') or []]
        result['login']['passkeys'] = sorted(passkey_fingerprint(k) for k in login.get('fido2Credentials') or [])
    result['archived'] = bool(item.get('archivedDate'))
    result['deleted'] = bool(item.get('deletedDate'))
    if result['card']:
        result['card'] = {k: result['card'].get(k) for k in ('cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code')}
    if result['identity']:
        result['identity'] = {k: result['identity'].get(k) for k in ('title', 'firstName', 'middleName', 'lastName',
            'address1', 'address2', 'address3', 'city', 'state', 'postalCode', 'country', 'company', 'email',
            'phone', 'ssn', 'username', 'passportNumber', 'licenseNumber')}
    if result['sshKey']:
        from cryptography.hazmat.primitives import serialization
        try:
            private = serialization.load_ssh_private_key(result['sshKey']['privateKey'].encode(), password=None)
            public = private.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        except (ValueError, TypeError, KeyError): raise MigrationError('Invalid SSH private key in a vault item.') from None
        result['sshKey'] = {'privatePublicKey': public, 'publicKey': result['sshKey'].get('publicKey'),
                            'keyFingerprint': result['sshKey'].get('keyFingerprint')}
    return result
