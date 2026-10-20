#!/usr/bin/env python3
"""Local migration runner. No 1Password write API is used by this tool."""
import argparse
import fcntl
import os
import stat
import sys
from contextlib import contextmanager
from pathlib import Path

from migration.client import Bitwarden
from migration.common import MigrationError, private_directory
from migration.engine import Engine


@contextmanager
def locked(workspace):
    root=private_directory(workspace)
    flags=os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW
    fd=os.open(root/'.lock',flags,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:
            raise MigrationError('Unsafe migration lock file.')
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise MigrationError('Another migration process is using this workspace.') from None
        yield
    finally: os.close(fd)


def parser():
    p=argparse.ArgumentParser(description='Migrate 1Password exports and iOS-transferred passkeys to Urbitwarden; leave 1Password intact.')
    commands=p.add_subparsers(dest='command',required=True)
    prepare=commands.add_parser('prepare',help='Inventory local .1pux exports; creates a private review workspace without network access.')
    prepare.add_argument('--source',type=Path,action='append',required=True,help='Repeat for every source account export.')
    prepare.add_argument('--work-dir',type=Path,required=True)
    prepare.add_argument('--server',required=True)
    prepare.add_argument('--email',required=True,help='The enrolled Urbitwarden email, not necessarily your 1Password email.')
    for name,help_text in (
        ('connect','Sign into a dedicated official CLI profile through Connect SSO and local unlock.'),
        ('capture-passkeys','Capture fingerprints of iOS-transferred passkeys for the source coverage review.'),
        ('plan','Validate review.json and record an exact transfer plan without changing vault content.'),
        ('apply','Apply or resume the recorded plan; then verify downloaded data.'),
        ('verify','Fresh sync and read-only verification against the original inputs and captured passkeys.')):
        child=commands.add_parser(name,help=help_text)
        child.add_argument('--work-dir',type=Path,required=True)
        child.add_argument('--bw',default='bw',help='Official Bitwarden CLI executable; no shell command strings.')
    return p


def main(argv=None):
    args=parser().parse_args(argv)
    os.umask(0o077)
    try:
        if args.command=='prepare':
            engine=Engine.prepare(args.work_dir,args.source,args.server,args.email)
            print(f'Inventoried {len(engine.source.records)} items and {len(engine.source.blobs)} archive members.')
            print('Review inventory.json and review.json in the private work directory. No vault changes made.')
            if engine.source.blockers:
                print('Source export has unresolved file problems; see inventory.json.',file=sys.stderr)
                return 2
            return 0
        with locked(args.work_dir):
            engine=Engine(args.work_dir)
            client=Bitwarden(args.bw,engine.root,engine.state['server'],engine.state['email'])
            # The session remains in memory; no passwords or session strings are written to the journal.
            client.connect()
            if args.command=='connect':
                engine.bind(client)
                print('Destination account verified. Each later invocation may request local unlock again.')
                return 0
            if args.command=='capture-passkeys':
                count=engine.capture(client)
                print(f'Captured {count} destination passkeys. Reconcile passkey-catalog.json with the source account inventory.')
                return 0
            if args.command=='plan':
                count=engine.plan(client)
                print(f'Planned {count} destination records. Review plan.json before apply; no vault content changed.')
                return 0
            report=engine.apply(client) if args.command=='apply' else engine.verify(client)
            print(f"Verified {report['native_items_verified']}/{report['native_items_expected']} records, "
                  f"{report['passkey_occurrences_verified']}/{report['passkey_occurrences_expected']} passkeys, "
                  f"and {report['files_verified']} file associations.")
            if report['complete']:
                print('Complete against the reviewed inventory. Source/passkey coverage and sign-in checks include owner attestations; see report.json.')
                return 0
            print(f"Incomplete: {len(report['issues'])} unresolved checks. See report.json. Keep 1Password intact.")
            return 2
    except KeyboardInterrupt:
        print('Interrupted. Keep the workspace and sources; rerun the same command to reconcile any pending write.',file=sys.stderr)
        return 130
    except MigrationError as error:
        print(str(error),file=sys.stderr); return 2
    except Exception as error:
        # Third-party exceptions may embed vault values, filenames or HTTP tokens.
        print('Migration stopped ('+type(error).__name__+'). Sensitive exception details were suppressed. Keep the workspace and sources.',file=sys.stderr)
        return 2


if __name__=='__main__': sys.exit(main())
