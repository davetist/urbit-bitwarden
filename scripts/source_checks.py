"""Check architecture and generated-source boundaries before packaging."""
from pathlib import Path
import hashlib,json,subprocess,sys
ROOT=Path(__file__).resolve().parents[3]
for name in ['bitwarden','grant-probe']:
 for rel in ['sur/connect.hoon','mar/connect-exchange.hoon','mar/connect-revoke.hoon']:
  assert(ROOT/'desk'/rel).read_bytes()==(ROOT/'integrations'/name/'desk'/rel).read_bytes(),f'Stale generic contract copy: {name}/{rel}'
for folder in ['desk','web/src']:
 for p in (ROOT/folder).rglob('*'):
  if p.is_file():
   s=p.read_text().lower()
   assert not any(x in s for x in ['bitwarden','offline_access','urbit-vault']),f'Client-specific behavior in generic source: {p}'
p=ROOT/'integrations/bitwarden/desk/lib/vault-assets.hoon';before=p.read_bytes()
subprocess.run([sys.executable,str(ROOT/'integrations/bitwarden/scripts/bundle.py')],check=True);assert p.read_bytes()==before,'Generated adapter assets were stale'
baseline=ROOT/'.work/bitwarden-sso/baseline-desk/lib/connect-auth.hoon'
if baseline.exists():assert(ROOT/'desk/lib/connect-auth.hoon').read_bytes()==baseline.read_bytes(),'Ordinary authorization core changed'
print('PASS generic source independence, contract copies, deterministic browser assets and unchanged ordinary auth core')
