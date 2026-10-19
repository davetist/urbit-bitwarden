from api import *
api=API();api.bootstrap();redirect='http://localhost:18065/callback'
start,q,verifier=api.begin('notes-native',redirect,'notes:read');cb=api.approve(start);assert cb['state'][0]==q['state']
code=cb['code'][0]
assert api.call('/connect/oauth/token',{'grant_type':'authorization_code','client_id':'notes-native','code':code,'redirect_uri':redirect,'code_verifier':verifier},form=True)[0]==400
for altered in [('wrong-client',code,redirect,verifier),('notes-native',code,redirect+'/',verifier),('notes-native',code,redirect,'A'*43)]:
 result=exchange_probe(*altered);assert isinstance(result,str) or result['status']==400
result=exchange_probe('notes-native',code,redirect,verifier);assert result['status']==200,('exchange',result.get('status'))
sid=result['grant']['sessionId'];assert scry('grant-probe','notes/'+sid) is not None
assert scry('connect','integration/urbitwarden/'+sid) is None
assert exchange_probe('notes-native',code,redirect,verifier)['status']==400
for callback in [redirect+'/',redirect.replace('18065','18066'),'http://evil.example:18065/callback']:
 assert api.begin('notes-native',callback,'notes:read')[0][0]==400
assert api.begin('notes-native',redirect,'documents:read')[0][0]==400
assert api.begin('notes-native',redirect,'api')[0][0]==400
assert api.call('/connect/owner/v1/revoke',{'sessionId':sid},owner=True)[0]==200
assert scry('grant-probe','notes/'+sid) is None
# An ordinary document client remains on its original opaque-token/strict-refresh path.
s,b,_=api.call('/connect/owner/v1/clients',{'id':'notes-document','name':'Existing notes document contract','redirectURI':'org.example.notes:/callback'},owner=True);assert s in (200,409)
start,q,v=api.begin('notes-document','org.example.notes:/callback','documents:read documents:write');cb=api.approve(start)
s,auth,_=api.call('/connect/oauth/token',{'grant_type':'authorization_code','client_id':'notes-document','code':cb['code'][0],'redirect_uri':'org.example.notes:/callback','code_verifier':v},form=True);assert s==200
s,rot,_=api.call('/connect/oauth/token',{'grant_type':'refresh_token','client_id':'notes-document','refresh_token':auth['refresh_token']},form=True);assert s==200
assert api.call('/connect/oauth/token',{'grant_type':'refresh_token','client_id':'notes-document','refresh_token':auth['refresh_token']},form=True)[0]==400
assert api.call('/connect/v1/collections/notes',token=rot['access_token'])[0]==401
report={'resource_consumer':'grant-probe notes','valid_exchange':True,'generic_http_cannot_exchange_resource_code':True,'wrong_client_pkce_callback_rejected':True,'single_use_code':True,'resource_isolation':True,'document_scope_isolation':True,'owner_revocation':True,'ordinary_document_consumer_strict_refresh_preserved':True}
(ROOT/'evidence/generic-contract.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS independent notes resource, PKCE/callback/client binding, single-use codes, isolation, revocation and unchanged document-client refresh.')
