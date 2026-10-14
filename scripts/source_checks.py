"""Check native desk contracts and deterministic generated browser assets."""
import subprocess
import sys
from connect_dependency import ROOT, CONNECT_ROOT, ensure_connect

ensure_connect()
for name, desk in [('bitwarden', ROOT / 'desk'), ('grant-probe', CONNECT_ROOT / 'integrations/grant-probe/desk')]:
    for relative in ['sur/connect.hoon', 'mar/connect-exchange.hoon', 'mar/connect-revoke.hoon']:
        assert (CONNECT_ROOT / 'desk' / relative).read_bytes() == (desk / relative).read_bytes(), f'Stale generic contract copy: {name}/{relative}'
for folder in ['desk', 'web/src']:
    for path in (CONNECT_ROOT / folder).rglob('*'):
        if path.is_file():
            source = path.read_text().lower()
            assert not any(word in source for word in ['bitwarden', 'offline_access', 'urbit-vault']), f'Client-specific behavior in generic source: {path}'
assets = ROOT / 'desk/lib/vault-assets.hoon'
before = assets.read_bytes()
subprocess.run([sys.executable, str(ROOT / 'scripts/bundle.py')], check=True)
assert assets.read_bytes() == before, 'Generated Bitwarden assets were stale'
baseline = ROOT / '.work/bitwarden-sso/baseline-desk/lib/connect-auth.hoon'
if baseline.exists():
    assert (CONNECT_ROOT / 'desk/lib/connect-auth.hoon').read_bytes() == baseline.read_bytes(), 'Ordinary authorization core changed from the optional fixture baseline'
print('PASS generic source independence, contract copies and deterministic browser assets')
