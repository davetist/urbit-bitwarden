import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from migration.common import read_json,write_json
from test_source import archive,item


class CliTests(unittest.TestCase):
    def test_full_terminal_workflow_uses_stdin_and_binary_readback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); work=root/'private'
            source=archive(root/'source.1pux',items=[item(state='archived',details={**item()['details'], 'documentAttributes':{
                'documentId':'doc','fileName':'upload.bin','decryptedSize':4}})],
                files={'files/doc___upload.bin':b'\x00\xff\x00a'})
            before=source.read_bytes()
            executable=root/'bw-double'
            executable.write_text('#!'+sys.executable+'\nimport sys\nsys.path.insert(0,'+
                                  repr(str(Path(__file__).parent))+')\nsys.path.insert(0,'+
                                  repr(str(Path(__file__).parent.parent))+')\nfrom bw_double import main\nmain()\n')
            executable.chmod(0o700)
            env={**os.environ,'MIGRATION_TEST_VAULT':str(root/'vault.json'),'PYTHONDONTWRITEBYTECODE':'1'}
            def run(*args):
                result=subprocess.run([sys.executable,'migrate.py',*args],env=env,capture_output=True,text=True,timeout=30)
                self.assertNotIn('sensitive-password',result.stdout+result.stderr)
                return result
            result=run('prepare','--source',str(source),'--work-dir',str(work),
                       '--server','https://ship.invalid/apps/urbitwarden','--email','me@example.invalid')
            self.assertEqual(result.returncode,0,result.stderr)
            for command in ('connect','capture-passkeys'):
                result=run(command,'--work-dir',str(work),'--bw',str(executable))
                self.assertEqual(result.returncode,0,result.stderr)
            review=read_json(work/'review.json'); review.update(source_scope_reviewed=True,
                representations_reviewed=True,passkey_inventory_reviewed=True,expected_passkey_count=0)
            write_json(work/'review.json',review)
            result=run('plan','--work-dir',str(work),'--bw',str(executable))
            self.assertEqual(result.returncode,0,result.stderr)
            result=run('apply','--work-dir',str(work),'--bw',str(executable))
            self.assertEqual(result.returncode,2,result.stderr)  # Missing the other-device observation.
            self.assertFalse(read_json(work/'report.json')['complete'])
            review['cross_client_sync_verified']=True; write_json(work/'review.json',review)
            result=run('verify','--work-dir',str(work),'--bw',str(executable))
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue(read_json(work/'report.json')['complete'])
            self.assertEqual(source.read_bytes(),before)
            for path in work.glob('*.json'): self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertFalse(list(work.glob('.upload-*')))


if __name__=='__main__': unittest.main()
