from pathlib import Path
import sys,subprocess,os
from install import control,ROOT
from fixture import WORK
tls=WORK/'tls';tls.mkdir(exist_ok=True,mode=0o700)
key=tls/'key.pem';cert=tls/'cert.pem'
if not key.exists():
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','30','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE'],check=True,capture_output=True)
    key.chmod(0o600)
def wain(p):return '~['+' '.join("'"+s+"'" for s in p.read_text().splitlines())+']'
try: control('=/  m  (strand ,vase)  ;<  ~  bind:m  (send-raw-card [%pass /tls %arvo %e %rule %cert [~ '+wain(key)+' '+wain(cert)+']])  ;<  ~  bind:m  (sleep ~s1)  (pure:m !>(~))')
except Exception: raise SystemExit('TLS install failed; private diagnostic suppressed')
print('Dedicated fixture now uses native Eyre TLS.')
