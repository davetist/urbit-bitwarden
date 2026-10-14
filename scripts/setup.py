"""Prepare the selected synthetic Bitwarden desk fixture; never real ships."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import urllib.request
from fixture import ROOT, WORK, ORIGIN, owned, running_process

SCRIPTS = Path(__file__).resolve().parent


def run(script, *args):
    subprocess.run([sys.executable, str(SCRIPTS / script), *args], check=True)


def prepare():
    owned(create=True)
    if running_process() is not None or (WORK / 'pier/.urb/conn.sock').exists():
        raise RuntimeError('Fixture already running; use existing setup or stop it first')
    WORK.chmod(0o700)
    # Detect unsupported syntax before acquiring resources or booting a ship.
    for script in SCRIPTS.glob('*.py'):
        compile(script.read_text(), str(script), 'exec')
    cfg = json.loads((ROOT / 'toolchain.json').read_text())
    for name in ('vere', 'pill'):
        item = cfg[name]; target = ROOT / item['localPath']
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            if name == 'pill':
                urllib.request.urlretrieve(item['url'], target)
            else:
                archive = WORK / 'vere.tgz'
                urllib.request.urlretrieve(item['archiveURL'], archive)
                if hashlib.sha256(archive.read_bytes()).hexdigest() != item['archiveSHA256']:
                    raise RuntimeError('Vere archive checksum mismatch')
                with tarfile.open(archive) as package:
                    member = next(m for m in package.getmembers() if m.isfile() and Path(m.name).name in ('vere', 'urbit', 'vere-v4.6-macos-aarch64'))
                    target.write_bytes(package.extractfile(member).read()); target.chmod(0o755)
        if hashlib.sha256(target.read_bytes()).hexdigest() != item['sha256']:
            raise RuntimeError(name + ' checksum mismatch')
    run('fetch_clients.py')
    if not (ROOT / 'web/node_modules/playwright').exists():
        subprocess.run(['npm', 'ci'], cwd=ROOT / 'web', check=True)
    subprocess.run(['npx', '--yes', 'playwright@1.62.1', 'install', 'chromium', '--no-shell'], cwd=ROOT / 'web', check=True)
    # Official CLI browser opener capture is test infrastructure, not a server.
    bindir = WORK / 'bin'; bindir.mkdir(exist_ok=True)
    shim = bindir / 'open'
    shim.write_text('''#!/usr/bin/env python3
import sys,json
from pathlib import Path
urls=[a for a in sys.argv[1:] if a.startswith(''' + repr(ORIGIN + '/') + ''')]
if len(urls)!=1:raise SystemExit('Unexpected browser destination')
p=Path(__file__).resolve().parents[1]/'cli-browser-url.json'
p.write_text(json.dumps({'url':urls[0]}));p.chmod(0o600)
''')
    shim.chmod(0o700)


def main():
    prepare()
    started = False
    try:
        run('start.py')
        started = True
        for script in ('tls.py', 'owner.py', 'bundle.py'): run(script)
        for desk in ('connect', 'bitwarden', 'grant-probe'): run('install.py', desk)
    except BaseException:
        if started:
            try: run('stop.py')
            except BaseException as cleanup:
                raise RuntimeError('Setup failed and fixture shutdown also failed; preserve the fixture and inspect its process identity') from cleanup
        raise
    print('Bitwarden desk fixture ready at ' + ORIGIN + '. Start browser.mjs --enroll.')


if __name__ == '__main__': main()
