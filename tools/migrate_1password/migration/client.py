"""The official CLI owns encryption. Its plaintext stdout stays inside this process."""
import base64
import getpass
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from .common import MigrationError, canonical, private_directory


def server_url(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path.rstrip('/') != '/apps/urbitwarden'):
        raise MigrationError('Use the exact HTTPS Urbitwarden server URL ending in /apps/urbitwarden.')
    return value.rstrip('/')


class Bitwarden:
    def __init__(self, executable, workspace, server, email):
        self.executable = str(executable)
        self.root = private_directory(workspace)
        self.server = server_url(server); self.email = email
        self.profile = self.root / 'bw-profile'
        private_directory(self.profile, create=True)
        self.env = dict(os.environ)
        if self.env.get('NODE_TLS_REJECT_UNAUTHORIZED')=='0':
            raise MigrationError('TLS verification must be enabled for credential migration.')
        # Keep a dedicated profile; never accidentally use the user's default vault/session.
        self.env.pop('BW_SESSION', None); self.env.pop('BW_PASSWORD', None)
        self.env.update(BITWARDENCLI_APPDATA_DIR=str(self.profile), BITWARDENCLI_DISABLE_UPDATE_NOTIFIER='true',
                        BW_NOINTERACTION='true', BW_RAW='true')
        if self.env.get('URBITWARDEN_MIGRATION_SESSION'):
            self.env['BW_SESSION'] = self.env.pop('URBITWARDEN_MIGRATION_SESSION')

    def run(self, *args, payload=None, binary=False):
        allowed = {('status',), ('sync',), ('list','items'), ('list','folders'), ('get','item'),
                   ('get','attachment'), ('create','item'), ('create','folder'), ('create','attachment'),
                   ('edit','item'), ('unlock','--passwordenv')}
        if not any(tuple(args[:len(prefix)]) == prefix for prefix in allowed):
            raise MigrationError('CLI operation is outside the migration allowlist.')
        body = base64.b64encode(canonical(payload)) if payload is not None else b''
        try:
            result = subprocess.run([self.executable, *args], input=body, env=self.env,
                                    capture_output=True, timeout=600, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise MigrationError('Bitwarden CLI could not complete the operation. Resume after checking connectivity.') from None
        if result.returncode:
            raise MigrationError('Bitwarden CLI operation failed; diagnostic output was suppressed to protect vault data.')
        if binary: return result.stdout
        if args[0] in ('sync', 'unlock'): return result.stdout.strip().decode()
        try: return json.loads(result.stdout)
        except (ValueError, UnicodeError): raise MigrationError('Bitwarden CLI returned an unexpected response.') from None

    def status(self): return self.run('status')

    def bind(self, expected_user=None):
        status = self.status()
        if status.get('serverUrl', '').rstrip('/') != self.server or status.get('userEmail', '').casefold() != self.email.casefold():
            raise MigrationError('CLI server/account does not match this migration workspace.')
        if status.get('status') != 'unlocked' or not status.get('userId'):
            raise MigrationError('CLI vault is not unlocked. Run connect or provide a local migration session.')
        if expected_user and status['userId'] != expected_user:
            raise MigrationError('Destination account identity changed.')
        return status['userId']

    def connect(self):
        status = self.status()
        if status.get('status') == 'unauthenticated':
            # This is the only server-setting path and only targets the new dedicated profile.
            configured = status.get('serverUrl')
            if configured and configured.rstrip('/') not in (self.server, 'https://vault.bitwarden.com'):
                raise MigrationError('Dedicated CLI profile is already configured for another server.')
            result = subprocess.run([self.executable, 'config', 'server', self.server], env=self.env,
                                    input=b'', capture_output=True, timeout=30)
            if result.returncode: raise MigrationError('Could not configure the dedicated CLI profile.')
            interactive = dict(self.env); interactive.pop('BW_NOINTERACTION', None); interactive.pop('BW_RAW', None)
            result = subprocess.run([self.executable, 'login', '--sso'], env=interactive, timeout=600)
            if result.returncode: raise MigrationError('SSO did not complete.')
            status = self.status()
        if status.get('serverUrl', '').rstrip('/') != self.server or status.get('userEmail', '').casefold() != self.email.casefold():
            raise MigrationError('SSO signed into a different destination account.')
        if status.get('status') == 'locked':
            self.env['URBITWARDEN_LOCAL_UNLOCK'] = getpass.getpass('Urbitwarden local vault password: ')
            try: self.env['BW_SESSION'] = self.run('unlock', '--passwordenv', 'URBITWARDEN_LOCAL_UNLOCK', '--raw')
            finally: self.env.pop('URBITWARDEN_LOCAL_UNLOCK', None)
        return self.bind()

    def sync(self): self.run('sync')
    def items(self):
        # CLI list defaults exclude archived/trash. Include tombstones so a resume
        # never mistakes a user-trashed imported record for a never-created one.
        found={}
        for flags in ((), ('--archived',), ('--trash',), ('--archived','--trash')):
            for item in self.run('list','items',*flags):
                previous=found.get(item['id'])
                if previous is not None and previous!=item:
                    raise MigrationError('Vault changed while listing item states; retry after syncing.')
                found[item['id']]=item
        return list(found.values())
    def folders(self): return self.run('list', 'folders')
    def get_item(self, item_id): return self.run('get', 'item', item_id)
    def create_item(self, payload): return self.run('create', 'item', payload=payload)
    def edit_item(self, item_id, payload): return self.run('edit', 'item', item_id, payload=payload)
    def create_folder(self, name): return self.run('create', 'folder', payload={'name': name})
    def upload(self, item_id, path): return self.run('create', 'attachment', '--file', str(path), '--itemid', item_id)
    def download(self, item_id, attachment_id):
        return self.run('get', 'attachment', attachment_id, '--itemid', item_id, '--raw', binary=True)
