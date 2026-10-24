"""Disposable native ships for the explicitly requested vault recovery rehearsal."""
from pathlib import Path
import argparse
import hashlib
import http.cookiejar as cookies
import http.client
import json
import os
import socket
import ssl
import subprocess
import time
import urllib.parse
import urllib.request

import deploy
from fixture import process_identity

ROOT=Path(__file__).resolve().parents[1]
WORK=Path(os.environ.get('URBITWARDEN_RECOVERY_TEST_ROOT',str(ROOT/'.work/vault-recovery'))).resolve()
SETTINGS={'source':('~zod',19880,19881,19882),'destination':('~nec',19890,19891,19892)}


def setup(name):
    ship,http,https,ames=SETTINGS[name]
    WORK.mkdir(parents=True,mode=0o700,exist_ok=True);WORK.chmod(0o700)
    folder=WORK/name
    marker=folder/'.recovery-test-owned'
    if folder.exists() and (not marker.is_file() or marker.read_text()!=str(ROOT)):
        raise RuntimeError('Refusing unowned test directory')
    folder.mkdir(parents=True,mode=0o700,exist_ok=True); marker.write_text(str(ROOT))
    pier=folder/'pier'
    if (folder/'process.json').exists():
        expected=json.loads((folder/'process.json').read_text()); actual=process_identity(expected['pid'])
        if actual and actual!=expected: raise RuntimeError('Test PID changed')
        if actual: return
    if (pier/'.urb').exists(): raise RuntimeError('Refusing to reuse stopped fixture; select a new test root')
    checks=[]
    try:
        for port,kind in [(http,socket.SOCK_STREAM),(https,socket.SOCK_STREAM),(ames,socket.SOCK_DGRAM)]:
            check=socket.socket(socket.AF_INET,kind);checks.append(check)
            if kind==socket.SOCK_STREAM:check.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            check.bind(('127.0.0.1',port))
            if kind==socket.SOCK_STREAM:check.listen(1)
    finally:
        for check in checks:check.close()
    vere=ROOT/'.work/toolchains/vere-4.6/vere-v4.6-macos-aarch64'
    pill=ROOT/'.work/toolchains/urbit-v4.6.pill'
    with (folder/'runtime.log').open('ab') as log:
        os.chmod(log.name,0o600)
        child=subprocess.Popen([str(vere),'-b','127.0.0.1','--http-port',str(http),'--https-port',str(https),'-p',str(ames),'-L','-t','-B',str(pill),'-F',ship[1:],'-c',str(pier)],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
    identity=process_identity(child.pid)
    (folder/'process.json').write_text(json.dumps(identity))
    for _ in range(600):
        if child.poll() is not None: raise RuntimeError('Test ship exited; inspect private log')
        if (pier/'.urb/conn.sock').exists() and (pier/'.run').exists():
            try:
                control=deploy.Control(pier)
                control.run(f'=/  m  (strand ,vase)  ;<  our=@p  bind:m  get-our  ?>  =(our {ship})  (pure:m !>(~))')
                break
            except (OSError,RuntimeError): pass
        time.sleep(.25)
    else: raise RuntimeError('Test ship boot timed out')
    (folder/'process.json').write_text(json.dumps(process_identity(child.pid)))
    print(name+': fresh native ship ready',flush=True)
    connect=Path(os.environ.get('URBIT_CONNECT_ROOT',str(ROOT.parent/'urbit-connect')))
    vault_source=Path(os.environ.get('URBITWARDEN_RECOVERY_DESK_ROOT',str(ROOT/'desk'))).resolve()
    for desk,src in [('connect',connect/'desk'),('urbitwarden',vault_source)]:
        entries={p.relative_to(src).as_posix():p.read_bytes() for p in sorted(src.rglob('*')) if p.is_file()}
        for expr in deploy.import_expressions(ship,desk,entries): control.run(expr)
        print(name+': installed '+desk,flush=True)
    tls=folder/'tls';tls.mkdir(mode=0o700)
    key=tls/'key.pem';cert=tls/'cert.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','7','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE'],capture_output=True,check=True)
    key.chmod(0o600)
    def wain(path):return '~['+' '.join("'"+line+"'" for line in path.read_text().splitlines())+']'
    control.run('=/  m  (strand ,vase)  ;<  ~  bind:m  (send-raw-card [%pass /tls %arvo %e %rule %cert [~ '+wain(key)+' '+wain(cert)+']])  (pure:m !>(~))')
    origin=f'https://localhost:{https}'
    code=deploy.cord(control.run('=/  m  (strand ,vase)  ;<  our=@p  bind:m  get-our  ;<  now=@da  bind:m  get-time  (pure:m !>((scot %p .^(@p %j /(scot %p our)/code/(scot %da now)/(scot %p our)))))')).lstrip('~')
    jar=cookies.CookieJar()
    opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=cert)),urllib.request.HTTPCookieProcessor(jar))
    with opener.open(urllib.request.Request(origin+'/~/login',data=urllib.parse.urlencode({'password':code}).encode()),timeout=30) as response:
        if response.status!=200: raise RuntimeError('Test owner login failed')
    private={'origin':origin,'ship':ship,'cookie':'; '.join(c.name+'='+c.value for c in jar)}
    owner=folder/'owner.json';owner.write_text(json.dumps(private));owner.chmod(0o600)
    print(name+': native TLS and owner session ready',flush=True)


def stop(name):
    folder=WORK/name
    if not (folder/'.recovery-test-owned').exists() or (folder/'.recovery-test-owned').read_text()!=str(ROOT): raise RuntimeError('Unowned fixture')
    expected=json.loads((folder/'process.json').read_text());actual=process_identity(expected['pid'])
    if actual is None:return
    if actual!=expected:raise RuntimeError('Test PID changed')
    control=deploy.Control(folder/'pier')
    try:control.run('=/  m  (strand ,vase)  ;<  ~  bind:m  (poke-our %hood %drum-exit !>(~))  (pure:m !>(~))')
    except (OSError,RuntimeError):pass
    for _ in range(100):
        if process_identity(expected['pid']) is None:
            print(name+': stopped',flush=True);return
        time.sleep(.1)
    raise RuntimeError('Test ship has not stopped; preserve process for inspection')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['setup','stop']);parser.add_argument('name',choices=SETTINGS)
    args=parser.parse_args();globals()[args.action](args.name)
