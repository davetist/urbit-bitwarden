"""Official CLI password fallback and callback-state rejection; isolated profiles."""
from api import *
from cli_ops import BW
import subprocess,os,time,signal
fixture=json.loads((WORK/'fixture.json').read_text())
base={**os.environ,'NODE_EXTRA_CA_CERTS':str(WORK/'tls/cert.pem'),'BITWARDENCLI_DISABLE_UPDATE_NOTIFIER':'true','BW_PASSWORD':fixture['password'],'PATH':str(WORK/'bin')+os.pathsep+os.environ['PATH']}
def env(name):return{**base,'BITWARDENCLI_APPDATA_DIR':str(WORK/name)}
def config(e):assert subprocess.run([BW,'config','server',ORIGIN],env=e,capture_output=True).returncode==0
passwordenv=env('cli-password-rejection');config(passwordenv)
r=subprocess.run([BW,'login',fixture['email'],'--passwordenv','BW_PASSWORD'],env=passwordenv,capture_output=True,text=True,timeout=40)
p=WORK/'password-rejection.json';p.write_text(json.dumps({'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}));p.chmod(0o600)
assert r.returncode!=0 and 'Password login is disabled.' in r.stderr,'Ordinary CLI password flow was not rejected at prelogin'
print('PASS official CLI password fallback rejected at SSO-only prelogin',flush=True)
stateenv=env('cli-state-rejection');config(stateenv)
urlfile=WORK/'cli-browser-url.json';prior=urlfile.stat().st_mtime_ns if urlfile.exists()else 0
with (WORK/'state-rejection.txt').open('w')as out:
 os.chmod(out.name,0o600)
 p=subprocess.Popen([BW,'login','--sso','urbit-vault'],env=stateenv,stdout=out,stderr=out,start_new_session=True)
 try:
  for _ in range(100):
   if urlfile.exists() and urlfile.stat().st_mtime_ns!=prior:break
   if p.poll()is not None:raise AssertionError('Official CLI exited before browser callback')
   time.sleep(.1)
  else:raise AssertionError('No official browser SSO callback')
  url=json.loads(urlfile.read_text())['url'];q=urllib.parse.parse_qs(urllib.parse.urlsplit(url).fragment.split('?',1)[1]);redirect=q['redirectUri'][0]
  assert redirect.startswith('http://localhost:806')
  a=API();a.bootstrap()
  start,_,_=a.begin('cli',redirect,'api offline_access',code_challenge=q['codeChallenge'][0],state=q['state'][0]+'_identifier=urbit-vault')
  approved=a.approve(start)
  callback=redirect+'?'+urllib.parse.urlencode({'code':approved['code'][0],'state':'wrong-state_identifier=urbit-vault'})
  try:
   with urllib.request.urlopen(callback,timeout=10)as response:response.read()
  except urllib.error.HTTPError as e:e.read()
  result=p.wait(timeout=20)
  assert result!=0
 finally:
  if p.poll()is None:os.killpg(p.pid,signal.SIGTERM);p.wait(timeout=5)
assert 'Something went wrong. Try again.' in (WORK/'state-rejection.txt').read_text()
print('PASS official CLI rejects callback state mismatch',flush=True)
(EVIDENCE/'official-negative.json').write_text(json.dumps({'official_cli_password_prelogin_rejected':True,'official_cli_wrong_callback_state_rejected_with_valid_code_and_matching_pkce_challenge':True},indent=2)+'\n')
