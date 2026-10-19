import argparse, pathlib, socket, subprocess, re, sys
from fixture import owned, WORK
owned()
PIER=WORK/'pier'
parser=argparse.ArgumentParser()
parser.add_argument('expression')
parser.add_argument('--card',action='store_true')
parser.add_argument('--khan',action='store_true')
parser.add_argument('--save-jam',choices=['connect','urbitwarden'])
args=parser.parse_args()
expr=args.expression.replace('\\','\\\\').replace("'","\\'")
thread='khan-eval' if args.khan else 'eval'
card=args.expression if args.card else f"[0 %fyrd %base %{thread} %noun %ted-eval '{expr}']"
if args.card:
 jam=subprocess.run([str(PIER/'.run'),'eval','-jn'],input=card.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout
else:
 from noun import jam as encode,cell
 payload=encode(cell(0,'fyrd','base',thread,'noun','ted-eval',args.expression))
 jam=b'\0'+len(payload).to_bytes(4,'little')+payload

with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
 s.settimeout(120)
 s.connect(str(PIER/'.urb/conn.sock'))
 s.sendall(jam)
 data=b''
 while len(data)<5:
  part=s.recv(5-len(data))
  if not part: raise RuntimeError('control socket closed before header')
  data+=part
 size=int.from_bytes(data[1:5],'little')
 while len(data)<5+size:
  part=s.recv(5+size-len(data))
  if not part: raise RuntimeError('control socket closed before payload')
  data+=part
if args.save_jam:
 target=PIER.parent/('state-'+args.save_jam+'.jam');target.write_bytes(data[5:]);target.chmod(0o600)
 print('Saved private Gall state response.');sys.exit(0)
out=subprocess.run([str(PIER/'.run'),'eval','-cn'],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
result=out.stdout.decode()
if not (result.startswith('[0 %avow 0 ') or result.startswith('[0 %peek ')):
 (PIER.parent/'control-error.txt').write_text(result)
 (PIER.parent/'control-error.txt').chmod(0o600)
 for match in re.finditer(r'\[%leaf ([0-9 ]+)\]',result):
  try:
   leaf=bytes(int(n) for n in match.group(1).split() if n!='0').decode()
   if len(leaf)>2 and not leaf.startswith('<[') and leaf not in {'sys','vane','clay','hoon','lib','app','gall','hood','spider','khan','dill','term'}: print(leaf,file=sys.stderr)
  except (ValueError,UnicodeDecodeError): pass
 sys.exit(1)
print(result,end='')
