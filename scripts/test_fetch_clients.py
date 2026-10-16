"""Pinned-client verification must survive optimized Python execution."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


SCRIPT = Path(__file__).resolve().parent / 'fetch_clients.py'


class FetchClientsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        scripts = self.root / 'scripts'; scripts.mkdir()
        (scripts / 'fetch_clients.py').write_bytes(SCRIPT.read_bytes())
        (scripts / 'fixture.py').write_text(
            "from pathlib import Path\nROOT=Path(__file__).resolve().parents[1]\n"
            "WORK=ROOT/'work'\nEVIDENCE=ROOT/'evidence'\n")
        self.source = self.root / 'source'; self.source.mkdir()
        self.runtime = self.root / '.work/toolchains/vere-4.6/vere-v4.6-macos-aarch64'
        self.runtime.parent.mkdir(parents=True)
        self.runtime.write_bytes(b'synthetic stock runtime')
        self.write_zip('cli', {'bw': b'synthetic CLI'})
        self.write_zip('browser', {'manifest.json': b'{"name":"synthetic"}'})
        self.write_manifest()

    def write_zip(self, name, files):
        with zipfile.ZipFile(self.source / (name + '.zip'), 'w') as archive:
            for path, data in files.items(): archive.writestr(path, data)

    def write_manifest(self):
        def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
        manifest = {name: {'url': 'https://example.invalid/' + name + '.zip',
                           'sha256': digest(self.source / (name + '.zip'))}
                    for name in ('cli', 'browser')}
        manifest['runtime'] = {'sha256': digest(self.runtime)}
        (self.root / 'artifacts.json').write_text(json.dumps(manifest))

    def run_helper(self):
        return subprocess.run([sys.executable, '-O', str(self.root / 'scripts/fetch_clients.py'),
                               '--from-directory', str(self.source)],
                              capture_output=True, text=True, timeout=15)

    def test_valid_pinned_clients_work_under_optimized_python(self):
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'work/vendor/cli/bw').read_bytes(), b'synthetic CLI')

    def test_archive_digest_mismatch_is_rejected_under_optimized_python(self):
        self.write_zip('cli', {'bw': b'substituted CLI'})
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('checksum mismatch', result.stderr)
        self.assertFalse((self.root / 'work/vendor/cli').exists())

    def test_unsafe_zip_path_is_rejected_under_optimized_python(self):
        self.write_zip('cli', {'bw': b'synthetic CLI', '../other': b'bad'})
        self.write_manifest()
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unsafe client archive path', result.stderr)

    def test_modified_extracted_file_is_rejected_under_optimized_python(self):
        self.assertEqual(self.run_helper().returncode, 0)
        (self.root / 'work/vendor/cli/bw').write_bytes(b'modified')
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Modified official client file', result.stderr)

    def test_extra_extracted_file_is_rejected_under_optimized_python(self):
        self.assertEqual(self.run_helper().returncode, 0)
        (self.root / 'work/vendor/cli/unlisted').write_bytes(b'substituted')
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Modified official client file', result.stderr)

    def test_duplicate_zip_member_is_rejected_under_optimized_python(self):
        with zipfile.ZipFile(self.source / 'cli.zip', 'w') as archive:
            archive.writestr('bw', b'first')
            archive.writestr('bw', b'second')
        self.write_manifest()
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unsafe client archive path', result.stderr)

    def test_runtime_digest_mismatch_is_rejected_under_optimized_python(self):
        self.runtime.write_bytes(b'substituted runtime')
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('runtime checksum mismatch', result.stderr)

    def test_live_fixture_api_refuses_optimized_python(self):
        result = subprocess.run([sys.executable, '-O', '-c',
                                 'import sys;sys.path.insert(0,' + repr(str(SCRIPT.parent)) + ');import api'],
                                capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Fixture API requires assertions', result.stderr)


if __name__ == '__main__': unittest.main()
