"""Locate the latest generic Connect source for development and source bundles.

Connect remains an independently installed native desk. The checkout here is a
build/test input, not a production service or a compatibility version pin.
"""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'https://github.com/davetist/urbit-connect.git'
BUNDLED = ROOT / 'dependencies/urbit-connect'
OVERRIDE = os.environ.get('URBIT_CONNECT_ROOT')
CONNECT_ROOT = Path(OVERRIDE).expanduser().resolve() if OVERRIDE else (
    BUNDLED if (BUNDLED / 'desk/app/connect.hoon').is_file()
    else ROOT / '.work/dependencies/urbit-connect')


def git(*args, cwd=None):
    cwd = CONNECT_ROOT if cwd is None else cwd
    return subprocess.run(['git', *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


def ensure_connect(refresh=False):
    if OVERRIDE or CONNECT_ROOT == BUNDLED:
        # Explicit developer checkouts and extracted archives are never mutated.
        if not (CONNECT_ROOT / 'desk/app/connect.hoon').is_file():
            raise RuntimeError('Connect source missing at URBIT_CONNECT_ROOT')
        return CONNECT_ROOT
    if not CONNECT_ROOT.exists():
        CONNECT_ROOT.parent.mkdir(parents=True, exist_ok=True)
        git('clone', '--depth', '1', '--branch', 'main', REPOSITORY,
            str(CONNECT_ROOT), cwd=CONNECT_ROOT.parent)
    elif not (CONNECT_ROOT / '.git').is_dir():
        raise RuntimeError('Connect cache is not a checkout; choose URBIT_CONNECT_ROOT')
    if git('remote', 'get-url', 'origin') != REPOSITORY:
        raise RuntimeError('Connect cache has an unexpected origin')
    if git('status', '--porcelain', '--untracked-files=normal'):
        raise RuntimeError('Connect cache has local changes; preserve them and choose URBIT_CONNECT_ROOT')
    if refresh:
        git('fetch', 'origin', 'main')
        git('merge', '--ff-only', 'FETCH_HEAD')
    if not (CONNECT_ROOT / 'desk/app/connect.hoon').is_file():
        raise RuntimeError('Connect desk is missing from its source checkout')
    return CONNECT_ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh', action='store_true', help='update the managed source cache to latest main')
    args = parser.parse_args()
    root = ensure_connect(refresh=args.refresh)
    print('Connect source:', root)


if __name__ == '__main__':
    main()
