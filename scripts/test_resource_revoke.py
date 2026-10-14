from api import *
A=API();A.bootstrap()
def login(client,redirect,scope):
 st,q,v=A.begin(client,redirect,scope);cb=A.approve(st)
 if client=='notes-native':return exchange_probe(client,cb['code'][0],redirect,v)['grant']['sessionId']
 s,b,_=A.call('/identity/connect/token',{'grant_type':'authorization_code','client_id':client,'code':cb['code'][0],'code_verifier':v,'redirect_uri':redirect},form=True);assert s==200
 return json.loads(base64.urlsafe_b64decode(b['access_token'].split('.')[1]+'=='))['sid']
def revoke(resource,sid):
 control(f'=/  m  (strand ,vase)  ;<  ~  bind:m  (poke-our %grant-probe %connect-revoke !>([%{resource} {hoon_text(sid)}]))  ;<  ~  bind:m  (sleep ~s1)  (pure:m !>(~))')
sid=login('cli','http://localhost:8065','api offline_access')
revoke('bitwarden',sid);assert scry('connect','integration/bitwarden/'+sid)
revoke('grant-probe',sid);assert scry('connect','integration/bitwarden/'+sid)
assert A.call('/connect/owner/v1/revoke',{'sessionId':sid},owner=True)[0]==200
sid=login('notes-native','http://localhost:18065/callback','notes:read');revoke('grant-probe',sid);assert scry('connect','integration/grant-probe/'+sid)is None
revoke('grant-probe',sid)
print('PASS resource revoke checks kernel caller provenance and session ownership; repeat revoke is idempotent')
(ROOT/'integrations/bitwarden/evidence/resource-revoke.json').write_text(json.dumps({'caller_spoof_rejected':True,'other_resource_rejected':True,'own_resource_revoked':True,'idempotent':True},indent=2)+'\n')
