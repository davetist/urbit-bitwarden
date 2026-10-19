"""Black-box reusable registration contract, dedicated fixture only."""
from pathlib import Path
import json,ssl,urllib.request,urllib.error
from install import ROOT
WORK=ROOT/'.work/urbitwarden-sso';origin='https://localhost:19681'
auth=json.loads((WORK/'owner.json').read_text())
ctx=ssl.create_default_context(cafile=WORK/'tls/cert.pem')
csrf=None
def request(path,data=None):
    headers={'Cookie':auth['cookie'],'Origin':origin}
    if csrf:headers['X-Connect-CSRF']=csrf
    if data is not None: headers['Content-Type']='application/json'
    req=urllib.request.Request(origin+path,data=None if data is None else json.dumps(data).encode(),headers=headers)
    try:r=urllib.request.urlopen(req,context=ctx)
    except urllib.error.HTTPError as e:r=e
    with r:
        raw=r.read()
        try:b=json.loads(raw)
        except ValueError:b={}
        return r.status,b
if __name__=='__main__':
    status,b=request('/connect/owner/v1/bootstrap');assert status==200,('bootstrap',status)
    csrf=b['csrf']
    assert request('/connect/owner/v1/configure',{'issuer':origin+'/connect'})[0]==200
    status,b=request('/connect/owner/v1/clients',{'id':'notes-native','name':'Independent notes resource','redirectURI':'http://localhost:18065/callback','integration':{'agent':'grant-probe','scopes':['notes:read'],'redirectURIs':['http://localhost:18065/callback']}})
    assert status==200,('reusable resource registration missing',status)
    print('PASS reusable loopback/resource registration')
