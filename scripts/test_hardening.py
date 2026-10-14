"""Resource release, ciphertext limits and stale-write tests against real Gall."""
from api import *
import time
A=API();A.bootstrap();passed=[]
def login():
 st,q,v=A.begin('cli','http://localhost:8065','api offline_access');cb=A.approve(st)
 s,b,_=A.call('/identity/connect/token',{'grant_type':'authorization_code','client_id':'cli','code':cb['code'][0],'code_verifier':v,'redirect_uri':'http://localhost:8065'},form=True);assert s==200;return b
b=login();sid=json.loads(base64.urlsafe_b64decode(b['access_token'].split('.')[1]+'=='))['sid']
assert scry('connect','integration/bitwarden/'+sid)
assert A.call('/identity/connect/revocation',{'token':b['refresh_token']},form=True)[0]==200
assert scry('connect','integration/bitwarden/'+sid) is None
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
 assert call('/api/ciphers',{'name':'2.'+'x'*65536})[0]==413
 assert call('/api/ciphers',{'name':'2.'+'x'*262144})[0]==413
 passed.append('stale writes, per-cipher and request-size limits')
 # Fill the byte budget with ciphertext-like strings, preserving original items.
 for i in range(80):
  s,row,_=call('/api/ciphers',{'name':'2.'+'x'*60000})
  if s==413:break
  assert s==200;created.append(row['id'])
 else:raise AssertionError('aggregate byte bound not enforced')
 assert i>50
 for id in created:assert call('/api/ciphers/'+id,method='DELETE')[0]==200
 created=[];passed.append('aggregate 4 MiB storage bound and hard-delete reclamation')
 existing=call('/api/ciphers')[1]['data'];initial=len(existing)
 for i in range(1000-initial):
  s,row,_=call('/api/ciphers',{'name':'2.count-limit','type':1});assert s==200;created.append(row['id'])
 assert call('/api/ciphers',{'name':'2.overflow'})[0]==429
 assert call('/api/ciphers/'+created[0]+'/delete',{},'PUT')[0]==200
 assert call('/api/ciphers',{'name':'2.soft-deleted-still-counts'})[0]==429
 assert call('/api/ciphers/'+created.pop(),method='DELETE')[0]==200
 s,row,_=call('/api/ciphers',{'name':'2.reclaimed'});assert s==200;created.append(row['id'])
 passed.append('1000 cipher bound includes soft-deleted items; hard delete frees capacity')
finally:
 for id in created:assert call('/api/ciphers/'+id,method='DELETE')[0]==200
assert A.call('/identity/connect/revocation',{'token':b['refresh_token']},form=True)[0]==200
print('\n'.join('PASS '+x for x in passed))
(EVIDENCE/'hardening.json').write_text(json.dumps({'passed':passed},indent=2)+'\n')
