"""Build a deterministic source bundle with the latest Connect development input."""
from pathlib import Path
import gzip
import hashlib
import io
import json
import subprocess
import tarfile

from connect_dependency import ROOT, CONNECT_ROOT, REPOSITORY, ensure_connect

EXCLUDED = {'.work', '.git', '.build', 'node_modules', 'dist', 'DerivedData',
            'xcuserdata', '__pycache__', '.DS_Store', 'test-results', 'playwright-report'}
SOURCE_GROUPS = ['desk', 'web', 'scripts', 'tests', 'docs', 'evidence', 'third_party', 'README.md',
                 'LICENSE', '.gitignore', 'artifacts.json', 'toolchain.json',
                 'package.json', 'package-lock.json']
# The complete generic source supports the inherited regression helpers too.
# This is a bundled dependency, never copied into this repository's tracked tree.
CONNECT_GROUPS = ['desk', 'web', 'scripts', 'tests', 'protocol', 'docs', 'third_party',
                  'integrations/grant-probe', 'sdk/swift', 'examples/ios-todo',
                  'Package.swift', 'toolchain.json', 'release/version.json', 'release/ownership.json',
                  'release/manifest.schema.json', 'release/source-files.json', 'release/README.md', 'README.md', 'LICENSE', '.gitignore']


def sources(root, groups):
    result = {}
    for group in groups:
        path = root / group
        if not path.exists():
            raise ValueError('Missing source package input: ' + str(path))
        candidates = [path] if path.is_file() else sorted(path.rglob('*'))
        for source in candidates:
            relative = source.relative_to(root)
            if EXCLUDED.intersection(relative.parts) or source.suffix in {'.pyc', '.xcuserstate'}:
                continue
            if source.is_symlink():
                raise ValueError('Symlink in source package input: ' + str(relative))
            if source.is_file():
                result[relative.as_posix()] = source.read_bytes()
    return result


def connect_provenance():
    try:
        top = subprocess.run(['git', 'rev-parse', '--show-toplevel'], cwd=CONNECT_ROOT,
                             capture_output=True, text=True, check=True).stdout.strip()
        if Path(top).resolve() != CONNECT_ROOT.resolve():
            raise ValueError('Bundled dependency is not a Git checkout')
        revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=CONNECT_ROOT,
                                  capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, ValueError, subprocess.CalledProcessError):
        revision = None
    return {'repository': REPOSITORY, 'compatibility': 'latest Connect desk',
            'sourceCommit': revision,
            'note': 'Build provenance only; this is not a required Connect version.'}


def build(entries):
    raw = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w') as package:
            for name, data in sorted(entries.items()):
                info = tarfile.TarInfo(name); info.mode = 0o644; info.size = len(data); info.mtime = 0
                package.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def main():
    ensure_connect(refresh=True)
    entries = sources(ROOT, SOURCE_GROUPS)
    entries.update({'dependencies/urbit-connect/' + name: data
                    for name, data in sources(CONNECT_ROOT, CONNECT_GROUPS).items()})
    entries['CONNECT-SOURCE.json'] = (json.dumps(connect_provenance(), indent=2) + '\n').encode()
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(entries.items())}
    entries['INTEGRATION-MANIFEST.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    data = build(entries)
    if data != build(entries):
        raise AssertionError('Non-deterministic source archive')
    output = ROOT / 'dist'; output.mkdir(exist_ok=True)
    target = output / 'urbitwarden-source.tgz'; target.write_bytes(data)
    with tarfile.open(target) as package:
        for name, digest in manifest.items():
            if hashlib.sha256(package.extractfile(name).read()).hexdigest() != digest:
                raise AssertionError('Source archive hash mismatch: ' + name)
    digest = hashlib.sha256(data).hexdigest()
    target.with_suffix('.tgz.sha256').write_text(digest + '  ' + target.name + '\n')
    print('PASS deterministic source archive and', len(manifest), 'file hashes:', digest)


if __name__ == '__main__':
    main()
