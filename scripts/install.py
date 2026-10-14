"""Install source desks only on the dedicated fake ship, via atomic Clay import."""
from pathlib import Path
import subprocess,sys,hashlib,json
from fixture import ROOT, CONNECT_ROOT
from connect_dependency import ensure_connect
CONTROL=Path(__file__).with_name('control.py')
def control(expr):
    print('Control request:',len(expr),'source characters',flush=True)
    r=subprocess.run([sys.executable,str(CONTROL),'--khan',expr],capture_output=True,text=True,timeout=240)
    if r.returncode: raise RuntimeError(r.stderr[:1600])
    print('Control completed',flush=True)
    return r.stdout

def install(name, source):
    if name not in ('connect','bitwarden','grant-probe'): raise ValueError('Unexpected fixture desk')
    control(f'=/  m  (strand ,vase)  ;<  now=@da  bind:m  get-time  ?:  (~(has in .^((set desk) %cd /~zod//(scot %da now))) %{name})  (pure:m !>(~))  ;<  ~  bind:m  (poke-our %hood %kiln-merge !>([%{name} ~zod %base da+now %init]))  ;<  ~  bind:m  (sleep ~s1)  (pure:m !>(~))')
    for hoon_phase in (True,False):
        prefix='=/  m  (strand ,vase)  ;<  now=@da  bind:m  get-time  '
        entries=[]
        for i,p in enumerate(sorted(source.rglob('*'))):
            if not p.is_file() or (p.suffix=='.hoon') != hoon_phase: continue
            mark=p.suffix[1:]; raw=p.read_bytes(); digits=format(int.from_bytes(raw,'little'),'x'); atom='0x'+'.'.join(reversed([digits[max(0,j-4):j] for j in range(len(digits),0,-4)]))
            path='/'+str(p.relative_to(source)).replace('.','/')
            prefix+=f'=/  tube{i}=tube:clay  .^(tube:clay %cc /~zod/{name}/(scot %da now)/mime/{mark})  '
            length = format(len(raw), ',').replace(',', '.')
            prefix+=f'=/  val{i}=vase  (tube{i} !>(`mime`[/text/plain [{length} {atom}]]))  '
            entries.append(f'[{path} %ins %{mark} val{i}]')
        control(prefix+f';<  ~  bind:m  (send-raw-card [%pass /import %arvo %c %info [%{name} %.y ~['+' '.join(entries)+']]])  ;<  ~  bind:m  (sleep ~s1)  (pure:m !>(~))')
    control(f'=/  m  (strand ,vase)  ;<  ~  bind:m  (poke-our %hood %kiln-install !>([%{name} ~zod %{name}]))  ;<  ~  bind:m  (sleep ~s1)  (pure:m !>(~))')
    print('Imported',name,'desk; compilation must be verified separately.')
if __name__=='__main__':
    name=sys.argv[1] if len(sys.argv)>1 else 'connect'
    if name not in ('connect','bitwarden','grant-probe'): raise ValueError('Unexpected fixture desk')
    if name!='bitwarden': ensure_connect()
    source={'bitwarden':ROOT/'desk','connect':CONNECT_ROOT/'desk','grant-probe':CONNECT_ROOT/'integrations/grant-probe/desk'}[name]
    install(name,source)
