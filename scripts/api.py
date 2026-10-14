"""Private fixture API with redirects disabled and certificate verification."""
import json,ssl,urllib.request,urllib.error,urllib.parse,secrets,hashlib,base64
from install import ROOT,control
from fixture import WORK, ORIGIN, EVIDENCE, BASE_PATH
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):return None
class API:
 def __init__(self):
  self.cookie=json.loads((WORK/'owner.json').read_text())['cookie']+'; connect-fixture-tests=1';self.csrf=None
  self.opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=WORK/'tls/cert.pem')))
 def call(self,path,data=None,method=None,owner=False,token=None,form=False,headers=None):
  if path.startswith(('/api/', '/identity/', '/vault/')):path=BASE_PATH+path
  h={};body=None
  if owner:h.update(Cookie=self.cookie,Origin=ORIGIN)
  if owner and self.csrf:h['X-Connect-CSRF']=self.csrf
  if token:h['Authorization']='Bearer '+token
  if data is not None:
   h['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json'
   body=(urllib.parse.urlencode(data) if form else json.dumps(data,separators=(',',':'))).encode()
  h.update(headers or {})
  try:r=self.opener.open(urllib.request.Request(ORIGIN+path,data=body,headers=h,method=method),timeout=35)
  except urllib.error.HTTPError as e:r=e
  with r:
   raw=r.read()
   try:b=json.loads(raw)
   except ValueError:b=None
   return r.status,b,dict(r.headers)
 def bootstrap(self):
  s,b,_=self.call('/connect/owner/v1/bootstrap',owner=True);assert s==200;self.csrf=b['csrf']
 def begin(self,client,redirect,scope,**extra):
  verifier=secrets.token_urlsafe(32)
  q={'response_type':'code','client_id':client,'redirect_uri':redirect,'scope':scope,'state':secrets.token_urlsafe(32),'code_challenge_method':'S256','code_challenge':base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()};q.update(extra)
  return self.call('/connect/oauth/authorize?'+urllib.parse.urlencode(q)),q,verifier
 def approve(self,start):
  s,_,h=start;assert s==302,('authorization',s)
  loc=h.get('location',h.get('Location'));rid=urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)['consent'][0]
  s,b,_=self.call('/connect/owner/v1/consents/'+rid,{'decision':'approve'},owner=True);assert s==200
  return urllib.parse.parse_qs(urllib.parse.urlsplit(b['redirect']).query)
def scry(agent,path):
 out=control(f'=/  m  (strand ,vase)  ;<  now=@da  bind:m  get-time  (pure:m !>((en:json:html .^(json %gx /~zod/{agent}/(scot %da now)/{path}/json))))').strip()
 text=out.removeprefix('[0 %avow 0 %noun ').removesuffix(']')
 if text.startswith("%"):
  text=text[1:]
 elif text.startswith("'"):text=text[1:-1].replace("\\'","'").replace('\\\\','\\')
 else:
  n=int(text,0);text=n.to_bytes((n.bit_length()+7)//8,'little').decode()
 return json.loads(text)
def hoon_text(s):return "'"+s.replace('\\','\\\\').replace("'","\\'")+"'"
def exchange_probe(client,code,redirect,verifier):
 vals=' '.join(map(hoon_text,['probe',client,code,redirect,verifier]))
 control(f'=/  m  (strand ,vase)  ;<  ~  bind:m  (poke-our %grant-probe %connect-exchange !>([{vals}]))  ;<  ~  bind:m  (sleep ~s1)  (pure:m !>(~))')
 return scry('grant-probe','result')
