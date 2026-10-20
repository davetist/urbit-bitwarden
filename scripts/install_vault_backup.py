"""Install a twice-daily user-systemd backup job after the first capture succeeds."""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
import sys

import deploy
import vault_backup


def unit_text(script, config, executable_path):
    # systemd is not a shell: quote arguments and escape '%' specifiers.
    def quote(value):
        return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'
    service = '\n'.join([
        '[Unit]', 'Description=Encrypted Urbitwarden vault backup',
        'After=network-online.target harbor.service', '', '[Service]', 'Type=oneshot',
        'UMask=0077', 'NoNewPrivileges=true',
        'Environment=' + quote('PATH=' + executable_path),
        'ExecStart=' + quote(sys.executable) + ' ' + quote(script) + ' run --config ' + quote(config),
        'TimeoutStartSec=30min', ''])
    timer = '''[Unit]
Description=Capture Urbitwarden vault every 12 hours

[Timer]
OnCalendar=*-*-* 00,12:00:00 Europe/Madrid
Persistent=true
RandomizedDelaySec=30
Unit=urbitwarden-backup.service

[Install]
WantedBy=timers.target
'''
    return service, timer


def install(config, apply=False):
    if not sys.platform.startswith('linux') or not shutil.which('systemctl'):
        raise RuntimeError('Automatic scheduling requires the Pi user systemd manager')
    config = deploy.no_symlinks(Path(config).resolve(strict=True))
    values = json.loads(config.read_text())
    control = deploy.Control(values['pier'], require_runtime=False)
    control.inspect(values['ship'])
    if not shutil.which('age'): raise RuntimeError('age is not on the service PATH')
    if values.get('remote') and not shutil.which('rclone'): raise RuntimeError('rclone is not on the service PATH')
    script = Path(__file__).with_name('vault_backup.py').resolve()
    service, timer = unit_text(script, config, os.environ['PATH'])
    unit_dir = Path.home()/'.config/systemd/user'
    unit_dir.mkdir(parents=True, exist_ok=True)
    targets = [(unit_dir/'urbitwarden-backup.service',service), (unit_dir/'urbitwarden-backup.timer',timer)]
    for target, content in targets:
        deploy.no_symlinks(target)
        if target.exists() and target.read_text()!=content:
            raise ValueError('Existing different backup unit requires explicit review')
    if not apply:return {'schedule':'every 12 hours','cloudConfigured':bool(values.get('remote')),'applied':False}
    # A successful manual capture precedes enablement; failures keep existing backups.
    result = vault_backup.scheduled(config)
    for target, content in targets:
        with target.open('w') as stream:
            os.chmod(target,0o600);stream.write(content)
    subprocess.run(['systemctl','--user','daemon-reload'],check=True,capture_output=True)
    subprocess.run(['systemctl','--user','enable','--now','urbitwarden-backup.timer'],check=True,capture_output=True)
    subprocess.run(['systemctl','--user','is-active','--quiet','urbitwarden-backup.timer'],check=True)
    return {'schedule':'every 12 hours','applied':True,**result}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',required=True,type=Path);parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    try:print(json.dumps(install(args.config,args.apply)))
    except Exception as error:
        print('Backup scheduling failed ('+type(error).__name__+').',file=sys.stderr);raise SystemExit(1)
