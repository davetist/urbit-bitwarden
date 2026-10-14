from cli_ops import *
from api import API
unlock();bw('sync',raw=True)
A=API();A.bootstrap()
# Remove only the extra disposable marker; retain the cross-client evidence item.
marker=WORK/'restart-marker.json'
if marker.exists():bw('delete','item',json.loads(marker.read_text())['id'],raw=True)
assert A.call('/connect/owner/v1/revoke',{'clientId':'cli'},owner=True)[0]==200
r=subprocess.run([BW,'sync'],env=env,capture_output=True,text=True,timeout=40)
p=WORK/'cli-revoked.json';p.write_text(json.dumps({'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}));p.chmod(0o600)
assert r.returncode!=0,'Official CLI unexpectedly synced after Connect revocation'
assert A.call('/connect/owner/v1/revoke',{'clientId':'browser'},owner=True)[0]==200
print('PASS official CLI sync denied after Connect revocation; extension grant also revoked')
(EVIDENCE/'native-revocation.json').write_text(json.dumps({'official_cli_sync_denied_after_connect_revoke':True,'extension_grant_revoked':True,'cached_local_decryption_not_erased':True},indent=2)+'\n')
