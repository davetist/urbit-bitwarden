"""Ownership and process identity for explicitly selected synthetic fixtures."""
from pathlib import Path
import json
import os
import subprocess

from connect_dependency import CONNECT_ROOT

ROOT = Path(__file__).resolve().parents[1]
NAME = os.environ.get('CONNECT_BW_FIXTURE', 'sso')
if NAME == 'sso':
    WORK = ROOT / '.work/bitwarden-sso'
    HTTP_PORT, HTTPS_PORT, AMES_PORT = 19680, 19681, 19682
    FIXTURE_ID = 'native-bitwarden-sso-v1'
elif NAME == 'review-fixes':
    WORK = ROOT / '.work/bitwarden-review-fixes'
    HTTP_PORT, HTTPS_PORT, AMES_PORT = 19780, 19781, 19782
    FIXTURE_ID = 'native-bitwarden-review-fixes-v1'
else:
    raise ValueError('Unknown CONNECT_BW_FIXTURE; use sso or review-fixes')
ORIGIN = f'https://localhost:{HTTPS_PORT}'
BASE_PATH = '/apps/bitwarden'
SERVER_URL = ORIGIN + BASE_PATH
EXPECTED = {'project': str(ROOT), 'fixture': FIXTURE_ID}
EVIDENCE = ROOT / 'evidence'
if NAME == 'review-fixes': EVIDENCE = EVIDENCE / 'review-fixes'


def owned(work=WORK, create=False):
    work = Path(work)
    if work.is_symlink() or any(p.is_symlink() for p in work.parents):
        raise ValueError('Refusing symlink fixture path')
    marker = work / '.owned-fixture.json'
    if marker.is_symlink():
        raise ValueError('Invalid fixture marker')
    if not marker.exists():
        if not create or (work.exists() and any(work.iterdir())):
            raise ValueError('Refusing nonempty or unowned fixture')
        work.mkdir(parents=True, mode=0o700, exist_ok=True)
        marker.write_text(json.dumps(EXPECTED)); marker.chmod(0o600)
    if json.loads(marker.read_text()) != EXPECTED:
        raise ValueError('Fixture belongs to another project')
    return work


def process_identity(pid):
    """A PID alone is insufficient: bind it to its start time and full command."""
    if not isinstance(pid, int) or pid <= 1:
        raise ValueError('Invalid fixture PID')
    result = subprocess.run(['ps', '-ww', '-p', str(pid), '-o', 'stat=', '-o', 'lstart=', '-o', 'command='],
                            capture_output=True, text=True, check=False)
    if not result.stdout.strip():
        if result.returncode not in (0, 1):
            raise RuntimeError('Could not inspect fixture process identity')
        return None
    fields = result.stdout.strip().split(None, 6)
    if len(fields) != 7:
        raise RuntimeError('Could not parse fixture process identity')
    if fields[0].startswith('Z'):
        return None
    return {'pid': pid, 'started': ' '.join(fields[1:6]), 'command': fields[6]}


def running_process(work=WORK):
    """Return a verified owned process, or refuse an ambiguous/reused PID."""
    work = owned(work)
    record = work / 'runtime-process.json'
    pidfile = work / 'runtime.pid'
    if record.is_symlink() or pidfile.is_symlink():
        raise ValueError('Refusing symlink process record')
    if record.exists():
        expected = json.loads(record.read_text())
        actual = process_identity(expected['pid'])
        if actual is not None and actual != expected:
            raise RuntimeError('Fixture PID identity changed; refusing to signal it')
        return actual
    if pidfile.exists() and process_identity(int(pidfile.read_text())) is not None:
        raise RuntimeError('Live fixture PID has no verified identity; preserve and investigate')
    return None
