"""Fetch or read locally cached pinned upstream archives; verify every extracted file."""
from pathlib import Path
import hashlib,json,zipfile,urllib.request,argparse,shutil,os
from fixture import ROOT, WORK, EVIDENCE
EVIDENCE.mkdir(parents=True,exist_ok=True)
p=argparse.ArgumentParser();p.add_argument('--from-directory',type=Path);args=p.parse_args()
vendor=WORK/'vendor';vendor.mkdir(parents=True,exist_ok=True)
manifest=json.loads((ROOT/'integrations/bitwarden/artifacts.json').read_text());verified={}
for name in ['cli','browser']:
 item=manifest[name];archive=vendor/(name+'.zip')
 if not archive.exists():
  if args.from_directory:shutil.copyfile(args.from_directory/(name+'.zip'),archive)
  else:urllib.request.urlretrieve(item['url'],archive)
 assert hashlib.sha256(archive.read_bytes()).hexdigest()==item['sha256'],name+' checksum mismatch'
 with zipfile.ZipFile(archive)as z:
  for info in z.infolist():
   assert not Path(info.filename).is_absolute() and '..' not in Path(info.filename).parts
  if not(vendor/name).exists():z.extractall(vendor/name)
  files=[x for x in z.infolist()if not x.is_dir()]
  for x in files:assert(vendor/name/x.filename).read_bytes()==z.read(x),'Modified official client file'
 verified[name]={'archive_sha256':item['sha256'],'extracted_files_compared':len(files),'unmodified':True}
(vendor/'cli/bw').chmod(0o755)
vere=ROOT/'.work/toolchains/vere-4.6/vere-v4.6-macos-aarch64'
assert hashlib.sha256(vere.read_bytes()).hexdigest()==manifest['runtime']['sha256']
verified['runtime']={'version':'4.6','sha256':manifest['runtime']['sha256'],'stock':True}
(EVIDENCE/'official-clients-unmodified.json').write_text(json.dumps(verified,indent=2)+'\n')
print('PASS pinned official CLI, extension and stock Vere artifact verification')
