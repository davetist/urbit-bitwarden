"""Private test-only owner login; never print the code or cookie."""
from install import ROOT,control
import re,json,urllib.request,urllib.parse,ssl,http.cookiejar,os
from fixture import WORK, ORIGIN
work=WORK
# The generator returns a cord; render only inside this private process.
out=control('=/  m  (strand ,vase)  ;<  our=@p  bind:m  get-our  ;<  now=@da  bind:m  get-time  (pure:m !>((scot %p .^(@p %j /(scot %p our)/code/(scot %da now)/(scot %p our)))))')
# Control prints nouns as decimal atoms, not aura strings.
raw=out.strip().removeprefix('[0 %avow 0 %noun ').removesuffix(']')
if raw.startswith("'") and raw.endswith("'"):
    code=raw[1:-1].lstrip('~')
else:
    value=int(raw)
    code=value.to_bytes((value.bit_length()+7)//8,'little').decode().lstrip('~')

jar=http.cookiejar.CookieJar()
opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=work/'tls/cert.pem')),urllib.request.HTTPCookieProcessor(jar))
with opener.open(urllib.request.Request(ORIGIN+'/~/login',data=urllib.parse.urlencode({'password':code}).encode())) as r: assert r.status==200
cookie='; '.join(c.name+'='+c.value for c in jar)
assert cookie
p=work/'owner.json';p.write_text(json.dumps({'code':code,'cookie':cookie}));p.chmod(0o600)
print('Dedicated owner session saved privately.')
