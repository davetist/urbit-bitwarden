"""First adapter HTTP contract: password prelogin must be SSO-only."""
import urllib.request,urllib.error,ssl,json
from fixture import WORK, ORIGIN
context=ssl.create_default_context(cafile=WORK/'tls/cert.pem')
req=urllib.request.Request(ORIGIN+'/identity/accounts/prelogin',data=b'{"email":"sso@example.invalid"}',headers={'Content-Type':'application/json'})
try:r=urllib.request.urlopen(req,context=context)
except urllib.error.HTTPError as e:r=e
with r:
 raw=r.read()
 try:b=json.loads(raw)
 except ValueError:b={}
 assert r.status==400 and b.get('error')=='sso_required',('SSO-only prelogin missing',r.status)
print('PASS SSO-only prelogin prevents the ordinary official-client password fallback')
