"""Resource release and stale-write checks; not a readiness gate."""
from api import *
import time
A=API();A.bootstrap();passed=[]
def login():
 st,q,v=A.begin('cli','http://localhost:8065','api offline_access');cb=A.approve(st)
 s,b,_=A.call('/identity/connect/token',{'grant_type':'authorization_code','client_id':'cli','code':cb['code'][0],'code_verifier':v,'redirect_uri':'http://localhost:8065'},form=True);assert s==200;return b
b=login();sid=json.loads(base64.urlsafe_b64decode(b['access_token'].split('.')[1]+'=='))['sid']
assert scry('connect','integration/urbitwarden/'+sid)
assert A.call('/identity/connect/revocation',{'token':b['refresh_token']},form=True)[0]==200
assert scry('connect','integration/urbitwarden/'+sid) is None
passed.append('adapter logout releases underlying Connect grant')
b=login();started=time.monotonic()
def call(path,data=None,method=None):
 global b,started
 if time.monotonic()-started>35:
  s,b,_=A.call('/identity/connect/token',{'grant_type':'refresh_token','client_id':'cli','refresh_token':b['refresh_token']},form=True);assert s==200;started=time.monotonic()
 return A.call(path,data,method,token=b['access_token'])
created=[]
try:
 s,item,_=call('/api/ciphers',{'name':'2.synthetic-encrypted-name','type':1});assert s==200;created.append(item['id'])
 s,updated,_=call('/api/ciphers/'+item['id'],{**item,'lastKnownRevisionDate':item['revisionDate']},'PUT');assert s==200 and updated['revisionDate']!=item['revisionDate']
 assert call('/api/ciphers/'+item['id'],{**item,'lastKnownRevisionDate':item['revisionDate']},'PUT')[0]==409
 passed.append('stale writes rejected without replacing stored data')
finally:
 for id in created:assert call('/api/ciphers/'+id,method='DELETE')[0]==200
assert A.call('/identity/connect/revocation',{'token':b['refresh_token']},form=True)[0]==200
print('\n'.join('PASS '+x for x in passed))
(EVIDENCE/'hardening.json').write_text(json.dumps({'passed':passed},indent=2)+'\n')
