from api import *
A=API();A.bootstrap()
def sessions():return {x['grant']['sessionId']for x in A.call('/connect/owner/v1/sessions',owner=True)[1]['sessions']}
for scope in ['api','offline_access']:
 before=sessions();st,q,v=A.begin('cli','http://localhost:8065',scope);cb=A.approve(st)
 s,b,_=A.call('/identity/connect/token',{'grant_type':'authorization_code','client_id':'cli','code':cb['code'][0],'code_verifier':v,'redirect_uri':'http://localhost:8065'},form=True)
 assert s==400 and b['error']=='invalid_grant'
 assert sessions()==before
print('PASS incomplete owner-approved scopes reject login and release Connect grant')
(ROOT/'integrations/bitwarden/evidence/partial-scope.json').write_text(json.dumps({'api_only_rejected_and_released':True,'offline_access_only_rejected_and_released':True},indent=2)+'\n')
