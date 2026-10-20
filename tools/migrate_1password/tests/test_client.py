import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

from migration.client import Bitwarden
from migration.common import MigrationError


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700)

    def test_stdin_payload_never_appears_in_argv_and_errors_are_redacted(self):
        client = Bitwarden('bw', self.root, 'https://host.invalid/apps/urbitwarden', 'person@example.invalid')
        with patch('subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=b'{"id":"x"}', stderr=b'')) as run:
            client.create_item({'name': 'secret-title', 'login': {'password': 'secret-value'}})
            args = run.call_args
            self.assertNotIn('secret', ' '.join(args.args[0]))
            self.assertTrue(args.kwargs['input'])
        with patch('subprocess.run', return_value=SimpleNamespace(returncode=1, stdout=b'secret-value', stderr=b'secret-value')):
            with self.assertRaises(MigrationError) as caught: client.sync()
            self.assertNotIn('secret-value', str(caught.exception))

    def test_wrong_server_or_account_is_refused(self):
        client = Bitwarden('bw', self.root, 'https://host.invalid/apps/urbitwarden', 'person@example.invalid')
        with patch.object(client, 'status', return_value={'status':'unlocked', 'serverUrl':'https://vault.bitwarden.com',
                                                       'userEmail':'person@example.invalid', 'userId':'id'}):
            with self.assertRaises(MigrationError): client.bind()

    def test_mutation_allowlist_excludes_source_and_destructive_operations(self):
        client = Bitwarden('bw', self.root, 'https://host.invalid/apps/urbitwarden', 'person@example.invalid')
        for args in [('delete','item','x'), ('purge',), ('config','server','https://elsewhere')]:
            with self.assertRaises(MigrationError): client.run(*args)

    def test_list_includes_archived_and_trashed_identities(self):
        client = Bitwarden('bw', self.root, 'https://host.invalid/apps/urbitwarden', 'person@example.invalid')
        def listing(*args, **kwargs):
            archived='--archived' in args; trash='--trash' in args
            return [{'id':str((archived,trash)), 'archivedDate':'date' if archived else None,
                     'deletedDate':'date' if trash else None}]
        with patch.object(client,'run',side_effect=listing):
            self.assertEqual(len(client.items()),4)

    def test_tls_verification_cannot_be_disabled_by_inherited_environment(self):
        with patch.dict(os.environ,{'NODE_TLS_REJECT_UNAUTHORIZED':'0'}):
            with self.assertRaises(MigrationError):
                Bitwarden('bw',self.root,'https://host.invalid/apps/urbitwarden','person@example.invalid')


if __name__ == '__main__': unittest.main()
