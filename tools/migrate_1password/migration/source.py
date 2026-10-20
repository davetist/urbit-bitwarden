"""Read 1PUX without extracting it; preserve every archive member and source record."""
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .common import MARKER, MigrationError, canonical, digest, file_digest, strict_json


def safe_name(name):
    return (isinstance(name, str) and bool(name) and name not in ('.', '..')
            and not any(c in name for c in '/\\\0') and all(ord(c) >= 32 for c in name))


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values(): yield from walk(child)
    elif isinstance(value, list):
        for child in value: yield from walk(child)


def strings(value):
    if isinstance(value, str): yield value
    elif isinstance(value, dict):
        for child in value.values(): yield from strings(child)
    elif isinstance(value, list):
        for child in value: yield from strings(child)


class SourceSet:
    def __init__(self, paths):
        self.archives, self.records, self.blobs, self.blockers = {}, {}, {}, []
        for path in paths: self._load(Path(path).resolve())
        if not self.records: raise MigrationError('The source set contains no vault items.')

    def _load(self, path):
        try:
            sha = file_digest(path)
            if sha in self.archives: raise MigrationError('The same source archive was supplied twice.')
            with zipfile.ZipFile(path) as z:
                infos = z.infolist(); names = set()
                for info in infos:
                    name = info.filename; pure = PurePosixPath(name)
                    if (name in names or pure.is_absolute() or '..' in pure.parts or '\\' in name
                            or str(pure) != name.rstrip('/') or '\x00' in name
                            or any(ord(c) < 32 for c in name)
                            or stat.S_ISLNK(info.external_attr >> 16) or info.flag_bits & 1):
                        raise MigrationError('Unsafe, duplicate or encrypted member in source archive.')
                    names.add(name)
                data_bytes = z.read('export.data'); data = strict_json(data_bytes)
                attributes = strict_json(z.read('export.attributes'))
                if not isinstance(attributes, dict) or attributes.get('version') != 3:
                    raise MigrationError('Only the documented 1PUX version 3 is supported.')
                if not isinstance(data, dict) or not isinstance(data.get('accounts'), list):
                    raise MigrationError('Invalid 1PUX account structure.')
                self.archives[sha] = {'sha256': sha, 'path': str(path), 'accounts': [],
                                      'key': 'archive:' + sha}
                local_records = []
                for account in data['accounts']:
                    aa = account['attrs']; aid = aa['uuid']
                    if not isinstance(aid, str) or not aid: raise MigrationError('Missing account identity.')
                    self.archives[sha]['accounts'].append(aid)
                    for vault in account['vaults']:
                        va = vault['attrs']; vid = va['uuid']
                        if not isinstance(vid, str) or not vid: raise MigrationError('Missing vault identity.')
                        for value in vault['items']:
                            iid = value['uuid']
                            if not isinstance(iid, str) or not iid: raise MigrationError('Missing item identity.')
                            key = 'source:' + digest([aid, vid, iid])
                            if key in self.records:
                                raise MigrationError('Duplicate account/vault/item identity across the source set.')
                            if not isinstance(value.get('details'), dict) or not isinstance(value.get('overview'), dict):
                                raise MigrationError('Invalid source item structure.')
                            self.records[key] = {'key': key, 'archive': sha, 'account': aa, 'vault': va,
                                'item': value, 'representation': representation(value.get('categoryUuid'))}
                            local_records.append(self.records[key])
                for info in infos:
                    if info.is_dir(): continue
                    body = z.read(info)
                    key = 'blob:' + digest([sha, info.filename])
                    metadata = info.filename in ('export.data', 'export.attributes')
                    owners = [self.archives[sha]['key']] if metadata else []
                    filename = PurePosixPath(info.filename).name
                    if '___' in filename and not metadata: filename = filename.split('___', 1)[1]
                    if not safe_name(filename): raise MigrationError('Unsafe attachment filename in source archive.')
                    self.blobs[key] = {'key': key, 'archive': sha, 'member': info.filename,
                        'name': filename, 'sha256': digest(body), 'size': len(body),
                        'owners': owners, 'metadata': metadata}
                # Resolve file IDs and explicit paths, never guess by a title or basename substring.
                local_blobs = [b for b in self.blobs.values() if b['archive'] == sha and not b['metadata']]
                for record in local_records:
                    for obj in walk(record['item']):
                        document_id = obj.get('documentId') or obj.get('documentID')
                        if not document_id: continue
                        matches = [b for b in local_blobs if PurePosixPath(b['member']).name.startswith(str(document_id) + '___')]
                        if len(matches) != 1:
                            self.blockers.append({'source': record['key'], 'reason': 'missing_or_ambiguous_file'})
                            continue
                        blob = matches[0]
                        if obj.get('decryptedSize') is not None and obj['decryptedSize'] != blob['size']:
                            self.blockers.append({'source': record['key'], 'reason': 'file_size_mismatch'})
                        if obj.get('fileName') and obj['fileName'] != blob['name']:
                            self.blockers.append({'source': record['key'], 'reason': 'file_name_mismatch'})
                        if record['key'] not in blob['owners']: blob['owners'].append(record['key'])
                    refs = set(strings(record['item']))
                    for blob in local_blobs:
                        if (blob['member'] in refs or PurePosixPath(blob['member']).name in refs):
                            if record['key'] not in blob['owners']: blob['owners'].append(record['key'])
        except MigrationError: raise
        except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, RuntimeError):
            raise MigrationError('Cannot read the source archive; validate its format and completeness.') from None

    def read_blob(self, key):
        blob = self.blobs[key]
        try:
            with zipfile.ZipFile(self.archives[blob['archive']]['path']) as z: data = z.read(blob['member'])
        except (OSError, KeyError, zipfile.BadZipFile):
            raise MigrationError('Cannot reread a source file; source may have changed.') from None
        if digest(data) != blob['sha256']: raise MigrationError('Source file changed after inventory.')
        return data

    def check_unchanged(self):
        if any(file_digest(a['path']) != a['sha256'] for a in self.archives.values()):
            raise MigrationError('A source archive changed. Start a separate migration workspace.')

    def inventory(self):
        return {'archives': list(self.archives.values()), 'items': [
            {'source': r['key'], 'account': r['account'].get('name', ''),
             'vault': r['vault'].get('name', ''), 'title': r['item']['overview'].get('title', ''),
             'category': r['item'].get('categoryUuid'), 'representation': r['representation']}
            for r in self.records.values()], 'files': list(self.blobs.values()), 'blockers': self.blockers}


LOGIN_CATEGORIES = {'001', '005', '102', '109', '110', '111', '112'}


def representation(category):
    if category in LOGIN_CATEGORIES: return 'login'
    return {'002': 'card', '003': 'secure_note', '004': 'identity', '114': 'ssh_key',
            '006': 'document_as_note_with_file'}.get(category, 'secure_note_with_all_fields')


def stamp(seconds):
    try: return datetime.fromtimestamp(float(seconds), timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    except (ValueError, TypeError, OverflowError, OSError):
        raise MigrationError('Unsupported timestamp in source item.') from None


def text_value(value):
    if isinstance(value, str): return value
    if isinstance(value, (dict, list, bool, int, float)) or value is None: return canonical(value).decode()
    raise MigrationError('Unsupported source field value.')


def convert_item(record):
    value = record['item']; details = value['details']; overview = value['overview']
    category = value.get('categoryUuid'); mode = representation(category)
    fields = []; slots = {}; otps = []; ssh = None
    for section in details.get('sections') or []:
        for field in section.get('fields') or []:
            raw = field.get('value', {}); key = str(field.get('id', ''))
            field_name = str(field.get('title') or key or 'Unnamed field')
            label = '/'.join(filter(None, [section.get('title'), field_name]))
            simple = next(iter(raw.values())) if isinstance(raw, dict) and len(raw) == 1 else raw
            if isinstance(raw, dict):
                if 'email' in raw and isinstance(raw['email'], dict): simple = raw['email'].get('email_address')
                if raw.get('totp'): otps.append(raw['totp'])
                if raw.get('sshKey'): ssh = raw['sshKey']
            slots.setdefault(key.lower(), simple)
            slots.setdefault(field_name.lower(), simple)
            fields.append({'name': label, 'value': text_value(raw if isinstance(simple, (dict, list)) else simple), 'type': 1})
    login_fields = details.get('loginFields') or []
    designated = {}
    for field in login_fields:
        if field.get('designation') in ('username', 'password'):
            designated[field['designation']] = field.get('value')
        fields.append({'name': 'Web form/' + str(field.get('name') or field.get('id') or 'field'),
                       'value': text_value(field.get('value', '')), 'type': 1})
    fields.extend([
        {'name': '1Password tags', 'value': canonical(overview.get('tags') or []).decode(), 'type': 0},
        {'name': MARKER, 'value': record['key'], 'type': 1}])
    result = {'type': 2, 'name': overview.get('title') or '(untitled)', 'notes': details.get('notesPlain') or '',
              'favorite': bool(value.get('favIndex', 0)), 'reprompt': 0, 'fields': fields,
              'secureNote': {'type': 0}, 'passwordHistory': [], 'organizationId': None}
    for previous in details.get('passwordHistory') or []:
        if 'value' not in previous or 'time' not in previous: raise MigrationError('Incomplete password history.')
        result['passwordHistory'].append({'password': previous['value'], 'lastUsedDate': stamp(previous['time'])})
    result['passwordHistory'].sort(key=lambda p: p['lastUsedDate'], reverse=True)
    if value.get('state') not in (None, 'active', 'archived'):
        raise MigrationError('Unsupported source item lifecycle state.')
    if value.get('state') == 'archived': result['archivedDate'] = stamp(value.get('updatedAt', 0))
    if mode == 'login':
        result['type'] = 1; result.pop('secureNote')
        urls = [u.get('url') for u in overview.get('urls') or []]
        urls.extend([overview.get('url'), slots.get('url'), slots.get('hostname'), slots.get('server'), slots.get('provider_website')])
        username = designated.get('username') or slots.get('username') or slots.get('pop_username')
        password = (designated.get('password') or details.get('password') or slots.get('password')
                    or slots.get('credential') or slots.get('pop_password'))
        result['login'] = {'username': username, 'password': password, 'totp': otps[0] if otps else None,
                           'uris': [{'uri': u, 'match': None} for u in dict.fromkeys(u for u in urls if isinstance(u, str) and u)],
                           'fido2Credentials': []}
    elif mode == 'card':
        result['type'] = 3; result.pop('secureNote')
        expiry = slots.get('expiry', '')
        expiry = str(expiry) if expiry is not None else ''
        result['card'] = {'cardholderName': slots.get('cardholder'), 'number': slots.get('ccnum'),
                          'brand': slots.get('type'), 'code': slots.get('cvv'),
                          'expMonth': expiry[-2:] if len(expiry) == 6 else None,
                          'expYear': expiry[:4] if len(expiry) == 6 else None}
    elif mode == 'identity':
        result['type'] = 4; result.pop('secureNote')
        mapping = {'title': 'title', 'firstname': 'firstName', 'initial': 'middleName', 'lastname': 'lastName',
                   'company': 'company', 'email': 'email', 'defphone': 'phone', 'username': 'username'}
        result['identity'] = {target: slots.get(source) for source, target in mapping.items()}
        address = next((v for v in slots.values() if isinstance(v, dict) and 'street' in v), {})
        result['identity'].update({target: address.get(source) for source, target in
            {'street': 'address1', 'city': 'city', 'state': 'state', 'zip': 'postalCode', 'country': 'country'}.items()})
    elif mode == 'ssh_key':
        from cryptography.hazmat.primitives import serialization
        raw = (ssh or {}).get('metadata', {}).get('privateKey') or (ssh or {}).get('privateKey')
        if not isinstance(raw, str): raise MigrationError('SSH item is missing private key material.')
        try:
            loader = serialization.load_ssh_private_key if 'BEGIN OPENSSH' in raw else serialization.load_pem_private_key
            key = loader(raw.encode(), password=None)
            private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                        serialization.NoEncryption()).decode()
            public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        except (ValueError, TypeError): raise MigrationError('Unsupported SSH key; source was preserved without mutation.') from None
        import base64, hashlib
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(public.split()[1])).digest()).decode().rstrip('=')
        result['type'] = 5; result.pop('secureNote')
        result['sshKey'] = {'privateKey': private, 'publicKey': public, 'keyFingerprint': fingerprint}
    return result


def metadata_item(archive):
    return {'type': 2, 'name': '1Password source metadata ' + archive['sha256'][:12],
            'notes': 'Original export metadata. Contains sensitive source records; attachments are encrypted by Bitwarden.',
            'secureNote': {'type': 0}, 'favorite': False, 'reprompt': 0, 'passwordHistory': [],
            'fields': [{'name': MARKER, 'type': 1, 'value': archive['key']}], 'organizationId': None}
