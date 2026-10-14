"""Real HTTP adapter authorization, refresh concurrency, expiry and revoke checks."""
from api import *
import concurrent.futures,time
A=API();A.bootstrap();CLIENT='cli';REDIRECT='http://localhost:8065'
def fresh():
 start,q,v=A.begin(CLIENT,REDIRECT,'api offline_access');cb=A.approve(start)
 form={'grant_type':'authorization_code','scope':'api offline_access','client_id':CLIENT,'code':cb['code'][0],'code_verifier':v,'redirect_uri':REDIRECT}
 return form
def exchange(form):return A.call('/identity/connect/token',form,form=True,headers={'Content-Type':'application/x-www-form-urlencoded; charset=utf-8'})
def login():
 f=fresh();s,b,_=exchange(f);assert s==200;return b
def refresh(auth,client=CLIENT):return A.call('/identity/connect/token',{'grant_type':'refresh_token','client_id':client,'refresh_token':auth['refresh_token']},form=True)
def sync(auth):return A.call('/api/sync',token=auth['access_token'])[0]
def revoke(auth):return A.call('/identity/connect/revocation',{'token':auth['refresh_token'],'client_id':CLIENT},form=True)[0]
def report_case(name):print('PASS',name,flush=True);passed.append(name)
passed=[]
f=fresh()
for changes in [{'code_verifier':'A'*43},{'redirect_uri':REDIRECT+'/'},{'client_id':'browser'},{'scope':'documents:read'}]:assert exchange({**f,**changes})[0]==400
s,a,_=exchange(f);assert s==200;assert exchange(f)[0]==400;report_case('wrong PKCE/callback/client/scope and reused code')
assert A.call('/api/sync',token='forged')[0]==401
assert A.call('/connect/v1/identity',token=a['access_token'])[0]==401
assert refresh(a,'browser')[0]==400;assert sync(a)==200;report_case('vault/document and refresh client isolation')
time.sleep(5.2)
with concurrent.futures.ThreadPoolExecutor(max_workers=6)as pool:results=list(pool.map(lambda _:refresh(a),range(6)))
assert all(s==200 for s,_,_ in results)
b=results[0][1];assert all(x[1]==b for x in results)
assert b['refresh_token']!=a['refresh_token'];assert sync(a)==401;assert sync(b)==200
report_case('six overlapping refreshes return one rotation')
assert revoke(a)==200;assert sync(b)==401;assert refresh(a)[0]==400;assert refresh(b)[0]==400
report_case('old refresh revocation during grace cannot resurrect session')
a=login();time.sleep(5.2);s,b,_=refresh(a);assert s==200;time.sleep(5.2);assert refresh(a)[0]==400;assert sync(b)==401;assert refresh(b)[0]==400
report_case('consumed refresh replay after grace invalidates family')
a=login();time.sleep(5.2);s,b,_=refresh(a);assert s==200
claims=json.loads(base64.urlsafe_b64decode(b['access_token'].split('.')[1]+'=='))
assert A.call('/connect/owner/v1/revoke',{'sessionId':claims['sid']},owner=True)[0]==200
assert sync(b)==401;assert refresh(a)[0]==400;assert refresh(b)[0]==400
report_case('Connect revocation checked before grace response')
a=login();expired=fresh();print('Waiting for real 60-second access/code expiry',flush=True);time.sleep(31);time.sleep(31)
assert sync(a)==401;assert exchange(expired)[0]==400;s,b,_=refresh(a);assert s==200 and sync(b)==200
report_case('actual access/code expiry and refresh recovery')
# An unsigned or unrelated owner context cannot approve a pending request.
start,q,v=A.begin(CLIENT,REDIRECT,'api offline_access');loc=start[2].get('location',start[2].get('Location'));rid=urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)['consent'][0]
assert A.call('/connect/owner/v1/consents/'+rid,{'decision':'approve'})[0]==401
assert A.call('/connect/owner/v1/consents/'+rid,{'decision':'approve'},owner=True,headers={'Origin':'https://evil.invalid'})[0]==403
assert A.call('/connect/owner/v1/consents/'+rid,{'decision':'approve'},owner=True,headers={'X-Connect-CSRF':'wrong'})[0]==403
report_case('unauthenticated, wrong-Origin and wrong-CSRF approval rejection')
(EVIDENCE/'adapter-contract.json').write_text(json.dumps({'passed':passed,'tests':'real Gall/Eyre HTTP; six concurrent refresh requests; actual elapsed expiry'},indent=2)+'\n')
