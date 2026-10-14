"""Run unchanged Connect HTTP assertions using only the owned SSO fixture.
Substitute infrastructure paths/control, never assertion bodies or responses.
"""
from api import WORK,ROOT,ORIGIN,API as FixtureAPI
from install import install,control
import sys,ssl,urllib.request,json,unittest,types,subprocess,os,signal,time,shutil
SCRIPTS=ROOT/'integrations/bitwarden/scripts';TESTS=ROOT/'tests/integration';sys.path.insert(0,str(TESTS));sys.path.insert(0,str(ROOT/'scripts'))
import support,targets,dev_ship
scratch=WORK/'regression-control';shutil.copytree(ROOT/'desk',scratch/'zod/connect',dirs_exist_ok=True)
class FixtureTargets:
 def require_owned(self):
  assert (WORK/'owner.json').is_file() and (WORK/'pier/.urb').is_dir();return self
 def state(self,name):assert name=='dev';return scratch
 def port(self,name):assert name=='http';return 19680
 def origin(self):return ORIGIN
targets.TARGETS=support.TARGETS=FixtureTargets();support.ORIGIN=ORIGIN
def init(self,origin=ORIGIN):
 self.origin=origin;self.owner_origin=ORIGIN;self.cookie=json.loads((WORK/'owner.json').read_text())['cookie']+'; connect-http-regression=1';self.csrf=None
 self.opener=urllib.request.build_opener(support.NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=WORK/'tls/cert.pem')))
support.API.__init__=init
original_run=subprocess.run
def start():
 original_run([sys.executable,str(SCRIPTS/'start.py')],check=True,capture_output=True)
 for _ in range(120):
  try:
   if FixtureAPI().call('/connect/v1/info')[0]==200:return
  except Exception:pass
  time.sleep(.25)
 raise AssertionError('Dedicated fixture did not restart')
def run(args,*a,**kw):
 if len(args)>1 and str(args[1])==str(ROOT/'scripts/dev_ship.py'):
  assert args[2:]==['start'];start();return subprocess.CompletedProcess(args,0,b'',b'')
 return original_run(args,*a,**kw)
subprocess.run=run
def rpc(state,action,**kw):
 if action=='command':
  if kw['command']=='|commit %connect':install('connect',scratch/'zod/connect');return{'output':'compiled'}
  assert kw['command']=='(div now ~m1)'
  out=control('=/  m  (strand ,vase)  ;<  now=@da  bind:m  get-time  (pure:m !>((div now ~m1)))');return{'output':'~zod:dojo> '+str(int(out.strip().removeprefix('[0 %avow 0 %noun ').removesuffix(']').replace('.',''),0))}
 if action=='stop':original_run([sys.executable,str(SCRIPTS/'stop.py')],check=True,capture_output=True);return{}
 assert action=='crash'
 pid=int((WORK/'runtime.pid').read_text());cmd=original_run(['ps','-p',str(pid),'-o','command='],capture_output=True,text=True,check=True).stdout
 assert str(WORK/'pier') in cmd and 'vere' in cmd
 os.killpg(pid,signal.SIGKILL)
 for _ in range(50):
  try:os.kill(pid,0)
  except ProcessLookupError:break
  time.sleep(.1)
 else:raise AssertionError('Owned runtime still alive')
 (WORK/'pier/.urb/conn.sock').unlink(missing_ok=True);return{}
dev_ship.rpc=rpc
# All previous SSO client workflows must be checked before destructive auth tests.
api=FixtureAPI();api.bootstrap()
original_clients=api.call('/connect/owner/v1/clients',owner=True)[1]['clients']
def clear_clients():
 s,b,_=api.call('/connect/owner/v1/clients',owner=True);assert s==200
 for c in b['clients']:
  assert api.call('/connect/owner/v1/clients/'+c['id']+'/remove',{'confirmClientId':c['id'],'confirmNamespace':c['namespace']},owner=True)[0]==200
modules=[]
for file in sorted(TESTS.glob('test_*.py')):
 name=file.stem;module=types.ModuleType(name);module.__file__=str(file);sys.modules[name]=module
 source=file.read_text().replace("ROOT/'.work/alpha/dev/zod/connect/app/connect.hoon'","TARGETS.state('dev')/'zod/connect/app/connect.hoon'")
 source=source.replace("ROOT / 'artifacts/alpha/reload-response.json'","ROOT / 'integrations/bitwarden/evidence/connect-reload-response.json'")
 if name=='test_info':
  source=source.replace('timeout=10)',"timeout=10,context=ssl.create_default_context(cafile=WORK/'tls/cert.pem'))")
  module.__dict__.update(ssl=ssl,WORK=WORK)
 module.__dict__['TARGETS']=targets.TARGETS
 exec(compile(source,str(file),'exec'),module.__dict__);modules.append(module)
resume=sys.argv[1]if len(sys.argv)>1 else None
results=[]
if resume:
 previous=json.loads((ROOT/'integrations/bitwarden/evidence/connect-regressions.json').read_text())
 results=[r for r in previous if r['module']<resume]
for module in modules:
 if resume and module.__name__<resume:continue
 api.bootstrap();clear_clients()
 suite=unittest.defaultTestLoader.loadTestsFromModule(module);result=unittest.TextTestRunner(verbosity=2).run(suite)
 results.append({'module':module.__name__,'run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped)})
 if not result.wasSuccessful():break
api.bootstrap();clear_clients()
for client in original_clients:
 registration={k:client[k]for k in ['id','name','redirectURI']}
 if 'integration' in client:registration['integration']=client['integration']
 assert api.call('/connect/owner/v1/clients',registration,owner=True)[0]==200
(ROOT/'integrations/bitwarden/evidence/connect-regressions.json').write_text(json.dumps(results,indent=2)+'\n')
assert all(not r['errors'] and not r['failures'] and not r['skipped']for r in results)
assert len(results)==len(modules)
