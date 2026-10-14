from api import *
a=API();a.bootstrap();start,q,v=a.begin('cli','http://localhost:8065','api offline_access');cb=a.approve(start)
s,b,_=a.call('/identity/connect/token',{'scope':'api offline_access','grant_type':'authorization_code','client_id':'cli','code':cb['code'][0],'code_verifier':v,'redirect_uri':'http://localhost:8065','deviceIdentifier':'http-probe','deviceType':'23','deviceName':'macos'},form=True,headers={'Content-Type':'application/x-www-form-urlencoded; charset=utf-8'})
print('Token status:',s,'response fields:',sorted(b or {}))
if s==200:
 p=WORK/'http-session.json';p.write_text(json.dumps(b));p.chmod(0o600)
 import base64
 claims=json.loads(base64.urlsafe_b64decode(b['access_token'].split('.')[1]+'=='))
 status,profile,_=a.call('/api/accounts/profile',token=b['access_token']);assert status==200 and profile['securityStamp']==claims['sstamp'] and claims['client_id']=='cli'
 print('Sync status:',a.call('/api/sync',token=b['access_token'])[0])
 print('Refresh status:',a.call('/identity/connect/token',{'grant_type':'refresh_token','client_id':'cli','refresh_token':b['refresh_token']},form=True)[0])
else:raise SystemExit('Token exchange failed')
