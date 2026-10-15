"""Independent check of every signed JWT issued by the adapter probe."""
from api import *
import hmac
# Read the active-state export as a noun with a small full decoder, then select state.
def cue(data):
 pos=0;memo={};stack=[]
 def read(n):
  nonlocal pos
  x=int.from_bytes(data[pos//8:(pos+n+7)//8],'little')>>(pos%8);pos+=n;return x&((1<<n)-1)if n else 0
 def rub():
  n=0
  while read(1)==0:n+=1
  if not n:return 0
  return read((1<<(n-1))+read(n-1))
 while True:
  at=pos
  if read(1)==0:v=rub();memo[at]=v
  elif read(1)==0:stack.append([at,None]);continue
  else:v=memo[rub()]
  while stack and stack[-1][1] is not None:
   at,left=stack.pop();v=(left,v);memo[at]=v
  if not stack:return v
  stack[-1][1]=v
# Connect's response is [0 %avow 0 %noun vault-state].
n=cue((WORK/'state-bitwarden.jam').read_bytes())
for _ in range(4):n=n[1]
state=n
assert state[0]==1
account=state[1][0];key=state[1][1][0]
auth=json.loads((WORK/'http-session.json').read_text());token=auth['access_token'];head,body,sig=token.split('.')
actual=base64.urlsafe_b64decode(sig+'==');expected=hmac.new(key.to_bytes(32,'little'),(head+'.'+body).encode(),hashlib.sha256).digest()
assert hmac.compare_digest(actual,expected)
print('PASS native Hoon HS256 matches independent standard HMAC for issued JWT')
