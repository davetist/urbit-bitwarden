"""Exercise stalled Gall exchanges on the owned fake ship, then restore both desks."""
from api import *
from install import install
import concurrent.futures,time,shutil
A=API();A.bootstrap()
def hood(mark,noun):return control(f'=/  m  (strand ,vase)  ;<  ~  bind:m  (poke-our %hood %{mark} !>({noun}))  (pure:m !>(~))')
def sessions():
 s,b,_=A.call('/connect/owner/v1/sessions',owner=True);assert s==200;return {x['grant']['sessionId']for x in b['sessions']}
passed=[]
for mode in ['timeout','reload']:
 before=sessions();st,q,v=A.begin('cli','http://localhost:8065','api offline_access');cb=A.approve(st)
 form={'grant_type':'authorization_code','client_id':'cli','code':cb['code'][0],'code_verifier':v,'redirect_uri':'http://localhost:8065'}
 hood('kiln-suspend-many','~[%connect]')
 try:
  with concurrent.futures.ThreadPoolExecutor()as pool:
   wait=pool.submit(A.call,'/identity/connect/token',form,form=True)
   time.sleep(.5);assert not wait.done()
   if mode=='reload':
    source=WORK/'pending-reload-desk';shutil.copytree(ROOT/'integrations/bitwarden/desk',source,dirs_exist_ok=True)
    p=source/'app/bitwarden.hoon';p.write_text(':: Pending response regression.\n'+p.read_text());install('bitwarden',source)
   s,b,_=wait.result(timeout=34);assert s==503 and b['error']=='temporarily_unavailable',(mode,s)
 finally:hood('kiln-revive','%connect')
 time.sleep(1)
 assert sessions()==before,'orphan exchange leaked a Connect grant'
 passed.append(mode+' completes HTTP with 503 and cleans late grant')
install('bitwarden',ROOT/'integrations/bitwarden/desk')
print('\n'.join('PASS '+x for x in passed))
(EVIDENCE/'pending.json').write_text(json.dumps({'passed':passed},indent=2)+'\n')
