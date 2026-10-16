"""Fetch or read locally cached pinned upstream archives; verify every extracted file."""
from pathlib import Path, PurePosixPath
import hashlib,json,zipfile,urllib.request,argparse,shutil,os
from fixture import ROOT, WORK, EVIDENCE

def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as stream:
  for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()

EVIDENCE.mkdir(parents=True,exist_ok=True)
p=argparse.ArgumentParser();p.add_argument('--from-directory',type=Path);args=p.parse_args()
vendor=WORK/'vendor';vendor.mkdir(parents=True,exist_ok=True)
manifest=json.loads((ROOT/'artifacts.json').read_text());verified={}
for name in ['cli','browser']:
 item=manifest[name];archive=vendor/(name+'.zip')
 if not archive.exists():
  if args.from_directory:shutil.copyfile(args.from_directory/(name+'.zip'),archive)
  else:urllib.request.urlretrieve(item['url'],archive)
 if digest(archive)!=item['sha256']:raise ValueError(name+' checksum mismatch')
 with zipfile.ZipFile(archive)as z:
  names=set()
  for info in z.infolist():
   path=PurePosixPath(info.filename)
   if (path.is_absolute() or '..' in path.parts or '\\' in info.filename or
       path.as_posix()!=info.filename.rstrip('/') or info.filename in names):
    raise ValueError('Unsafe client archive path')
   names.add(info.filename)
  target=vendor/name
  if target.is_symlink():raise ValueError('Modified official client directory')
  if not target.exists():z.extractall(target)
  files=[x for x in z.infolist()if not x.is_dir()]
  expected={x.filename for x in files}
  for path in target.rglob('*'):
   if path.is_symlink() or path.is_file() and path.relative_to(target).as_posix() not in expected:
    raise ValueError('Modified official client file')
  for x in files:
   if (target/x.filename).read_bytes()!=z.read(x):raise ValueError('Modified official client file')
 verified[name]={'archive_sha256':item['sha256'],'extracted_files_compared':len(files),'unmodified':True}
(vendor/'cli/bw').chmod(0o755)
vere=ROOT/'.work/toolchains/vere-4.6/vere-v4.6-macos-aarch64'
if digest(vere)!=manifest['runtime']['sha256']:raise ValueError('runtime checksum mismatch')
verified['runtime']={'version':'4.6','sha256':manifest['runtime']['sha256'],'stock':True}
(EVIDENCE/'official-clients-unmodified.json').write_text(json.dumps(verified,indent=2)+'\n')
print('PASS pinned official CLI, extension and stock Vere artifact verification')
