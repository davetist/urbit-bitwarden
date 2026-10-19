"""Read-only raw and decoded-event audit; outputs only aggregate evidence."""
from pathlib import Path
import json,hashlib,base64,mmap,sys,urllib.parse
import lmdb
from noun import scan_atoms
from fixture import ROOT, WORK, EVIDENCE
f=json.loads((WORK/'fixture.json').read_text());password=f['password'].encode();email=f['email'].encode()
master=hashlib.pbkdf2_hmac('sha256',password,email,600000,32)
auth=hashlib.pbkdf2_hmac('sha256',master,password,1,32)
secrets={'password':password,'master_key':master,'authentication_hash_raw':auth,'authentication_hash_base64':base64.b64encode(auth)}
for i,key in enumerate(json.loads((WORK/'enrollment-plaintexts.json').read_text())):
 b=bytes(key);secrets['enrollment_plaintext_'+str(i)]=b;secrets['enrollment_plaintext_base64_'+str(i)]=base64.b64encode(b)
for k,v in list(secrets.items()):
 if 'base64' not in k:
  secrets[k+'_base64']=base64.b64encode(v)
  secrets[k+'_base64url']=base64.urlsafe_b64encode(v).rstrip(b'=')
for k,v in list(secrets.items()):
 if k.endswith(('base64','base64url')) or k=='password':secrets[k+'_form_encoded']=urllib.parse.quote_from_bytes(v,safe='').encode()
def patterns(b):return [(int.from_bytes(b,'little')<<s).to_bytes(len(b)+1,'little')[1:-1]for s in range(8)]
traffic=json.loads((WORK/'browser-traffic.json').read_text())
enrollment=next(json.loads(r['body']) for r in traffic if r['url'].endswith('/vault/enroll') and r.get('body'))
positive={'encrypted_user_key':enrollment['key'].encode(),'owner_cookie':json.loads((WORK/'owner.json').read_text())['cookie'].split(';')[0].split('=',1)[1].encode(),'issued_access_token':json.loads((WORK/'http-session.json').read_text())['access_token'].encode()}
positivehits={k:0 for k in positive}
rawhits={k:False for k in secrets};decoded={k:0 for k in secrets};http=[];forms=[];decoded_count=0;atoms=0;failures=[];first=None;last=None
for file in (WORK/'pier/.urb/log').glob('*/data.mdb'):
 with file.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
  for k,v in secrets.items():rawhits[k]|=any(mm.find(p)>=0 for p in patterns(v))
 e=lmdb.open(str(file.parent),readonly=True,lock=False,max_dbs=8);db=e.open_db(b'EVENTS')
 with e.begin(db=db) as tx:
  for key,val in tx.cursor():
   event=int.from_bytes(key,'little')
   # Start before enrollment, at the first synthetic-account identifier input.
   if first is None and any(p in val for p in patterns(email)):first=event
   if first is None:continue
   last=event
   def visit(n):
    b=n.to_bytes((n.bit_length()+7)//8,'little')
    for k,v in secrets.items():
     if v in b:decoded[k]+=1
    for k,v in positive.items():
     if v in b:positivehits[k]+=1
    if len(b)>262144:return
    try:s=b.decode('utf-8')
    except UnicodeDecodeError:return
    if s.startswith('/') and len(s)<2048:
     path=urllib.parse.urlsplit(s).path
     if path.startswith(('/identity/','/api/','/vault/','/connect/')):http.append(path)
    if 'grant_type=' in s and not ('\n' in s) and len(s)<16384:
     p=urllib.parse.parse_qs(s)
     if 'grant_type' in p:forms.append({'event':event,'grant_type':p['grant_type'][0],'fields':sorted(p),'client_id':p.get('client_id',[''])[0]})
   try:atoms+=scan_atoms(val[4:],visit);decoded_count+=1
   except Exception as err:failures.append({'event':event,'error':str(err)})
 e.close()
active={}
for agent in ['connect','urbitwarden']:
 path=WORK/('state-'+agent+'.jam')
 matches={k:0 for k in secrets}
 def state_visit(n):
  b=n.to_bytes((n.bit_length()+7)//8,'little')
  for k,v in secrets.items():
   if v in b:matches[k]+=1
 count=scan_atoms(path.read_bytes(),state_visit)
 active[agent]={'decoded_atoms':count,'known_secret_matches':matches}
 assert not any(matches.values())
report={'method':'Read-only full LMDB raw byte scan at all eight bit offsets, plus iterative jam literal-atom decoding of EVENTS values after the synthetic account first appears; first four bytes are the runtime mug per stock Vere disk.c. Backreferences refer to already scanned atoms/cells.','active_gall_state':active,'decoded_event_positive_controls':positivehits,'raw_database_secret_matches':rawhits,'decoded_event_secret_matches':decoded,'decoded_event_range':[first,last],'decoded_events':decoded_count,'decoded_literal_atoms':atoms,'decode_failures':failures,'observed_paths':sorted(set(http)),'token_request_metadata':forms,'limitations':['This is evidence for these synthetic credentials and exercised flows, not a proof about arbitrary client actions or encodings.','Earlier kernel boot events are raw-scanned, not decoded.','Owner cookies, authorization codes, access/refresh tokens and encrypted key envelopes remain journaled.','Input-event inspection is distinct from active Gall state inspection.']}
(EVIDENCE/'history-audit.json').write_text(json.dumps(report,indent=2)+'\n')
print('Decoded events:',decoded_count,'range:',first,last,'decode failures:',len(failures),'known-secret matches:',any(rawhits.values())or any(decoded.values()))
assert all(positivehits.values()),'Audit positive control missing'
assert first is not None and decoded_count>0 and not failures and not any(rawhits.values()) and not any(decoded.values())
