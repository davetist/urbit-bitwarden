"""Unmodified official CLI operations; password used only for local unlock."""
import os,subprocess,json,sys
from api import ROOT,WORK,ORIGIN,EVIDENCE
BW=str(WORK/'vendor/cli/bw')
fixture=json.loads((WORK/'fixture.json').read_text())
env={**os.environ,'BITWARDENCLI_APPDATA_DIR':str(WORK/'cli-profile'),'NODE_EXTRA_CA_CERTS':str(WORK/'tls/cert.pem'),'BITWARDENCLI_DISABLE_UPDATE_NOTIFIER':'true','BW_PASSWORD':fixture['password']}
def bw(*args,input=None,raw=False):
 r=subprocess.run([BW,*args],input=input,env=env,capture_output=True,text=True,timeout=90)
 if r.returncode:
  p=WORK/'cli-error.json';p.write_text(json.dumps({'command':args[0],'returncode':r.returncode,'stderr':r.stderr}));p.chmod(0o600)
  raise RuntimeError('Official CLI '+args[0]+' failed; private diagnostic saved.')
 if raw:return r.stdout.strip()
 try:return json.loads(r.stdout or 'null')
 except json.JSONDecodeError:
  p=WORK/'cli-error.json';p.write_text(json.dumps({'command':args[0],'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}));p.chmod(0o600)
  raise RuntimeError('Official CLI '+args[0]+' returned non-JSON output; private diagnostic saved.') from None
def unlock():
 env['BW_SESSION']=bw('unlock','--passwordenv','BW_PASSWORD','--raw',raw=True)
 p=WORK/'cli-session.json';p.write_text(json.dumps({'session':env['BW_SESSION']}));p.chmod(0o600)
 print('PASS official CLI local vault unlock')
if __name__=='__main__':
 op=sys.argv[1]
 if op=='status':print(bw('status')['status'])
 else:
  unlock()
  bw('sync',raw=True);print('PASS official CLI sync')
  if op=='create':
   item=bw('get','template','item');item.update(name='Connect SSO proof',notes='Synthetic client-encrypted integration evidence',type=1)
   item['login']={'username':'sso-demo','password':'synthetic-item-only','uris':[{'match':None,'uri':'https://example.invalid'}]}
   created=bw('create','item',bw('encode',input=json.dumps(item),raw=True));assert created['name']==item['name']
   (EVIDENCE/'item-id.txt').write_text(created['id'])
   print('PASS official CLI encrypted item creation')
  elif op=='read':
   item=bw('get','item',(EVIDENCE/'item-id.txt').read_text().strip())
   print('Item name:',item['name']);assert item['login']['password']=='synthetic-item-only'
  elif op=='delete':
   item=bw('get','template','item');item.update(name='Disposable SSO item',type=1);item['login']={'username':'delete-only','password':'synthetic-delete','uris':[]}
   created=bw('create','item',bw('encode',input=json.dumps(item),raw=True));bw('delete','item',created['id'],raw=True);bw('sync',raw=True)
   assert created['id'] not in [x['id']for x in bw('list','items')]
   print('PASS official CLI encrypted creation/deletion and sync')
