from api import *
import subprocess,time,sys
from pathlib import Path
A=API();A.bootstrap()
def login():
 st,q,v=A.begin('cli','http://localhost:8065','api offline_access');cb=A.approve(st)
 s,b,_=A.call('/identity/connect/token',{'scope':'api offline_access','grant_type':'authorization_code','client_id':'cli','code':cb['code'][0],'code_verifier':v,'redirect_uri':'http://localhost:8065'},form=True);assert s==200;return b
def refresh(a):return A.call('/identity/connect/token',{'grant_type':'refresh_token','client_id':'cli','refresh_token':a['refresh_token']},form=True)
a=login();time.sleep(5.2);s,b,_=refresh(a);assert s==200
started=time.monotonic()
subprocess.run([sys.executable,str(Path(__file__).with_name('stop.py'))],check=True)
subprocess.run([sys.executable,str(Path(__file__).with_name('start.py'))],check=True)
for i in range(120):
 try:
  if A.call('/connect/v1/info')[0]==200:break
 except Exception:pass
 time.sleep(.25)
else:raise AssertionError('Fixture did not resume')
elapsed=time.monotonic()-started
s,retry,_=refresh(a)
if elapsed<5:assert s==200 and retry==b;grace='same response retained across restart'
else:assert s==400;grace='expired predecessor rejected after restart'
# The original official CLI session must still sync/decrypt the preserved browser edit.
r=subprocess.run([sys.executable,str(Path(__file__).with_name('cli_ops.py')),'read'],capture_output=True,text=True,timeout=180)
assert r.returncode==0,'Official CLI post-restart workflow failed; inspect dedicated logs'
assert 'Connect SSO proof — extension edit' in r.stdout
print('PASS full stock-Vere restart and official CLI decryption; refresh:',grace,flush=True)
(EVIDENCE/'restart.json').write_text(json.dumps({'runtime_restart_seconds':elapsed,'refresh_grace_result':grace,'official_cli_local_unlock_sync_decrypt_after_restart':True,'retained_extension_edit':True},indent=2)+'\n')
