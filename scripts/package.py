"""Deterministic integration source bundle; never overwrite alpha release artifacts."""
from pathlib import Path
import gzip,io,tarfile,hashlib,json
ROOT=Path(__file__).resolve().parents[3];out=ROOT/'integrations/bitwarden/dist';out.mkdir(exist_ok=True)
# Existing release source selection preserves the full reusable project prerequisites.
import sys
sys.path.insert(0,str(ROOT/'scripts'))
from release_check import SOURCE_GROUPS,source_files
paths={p.relative_to(ROOT).as_posix():p for group in SOURCE_GROUPS+['integrations/bitwarden','integrations/grant-probe']for p in source_files(group)}
# Never ship private state, third-party executable artifacts, caches, or this output.
assert all(not any(x in Path(n).parts for x in ['.work','vendor','dist','node_modules','__pycache__'])for n in paths)
manifest={n:hashlib.sha256(p.read_bytes()).hexdigest()for n,p in sorted(paths.items())}
entries={n:p.read_bytes()for n,p in paths.items()};entries['INTEGRATION-MANIFEST.json']=(json.dumps(manifest,indent=2)+'\n').encode()
def build():
 raw=io.BytesIO()
 with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0)as z,tarfile.open(fileobj=z,mode='w')as t:
  for n,b in sorted(entries.items()):
   i=tarfile.TarInfo(n);i.mode=0o644;i.size=len(b);i.mtime=0;t.addfile(i,io.BytesIO(b))
 return raw.getvalue()
a=build();assert a==build();file=out/'connect-bitwarden-sso-source.tgz';file.write_bytes(a)
with tarfile.open(file)as t:
 for n,d in manifest.items():assert hashlib.sha256(t.extractfile(n).read()).hexdigest()==d
sha=hashlib.sha256(a).hexdigest();file.with_suffix('.tgz.sha256').write_text(sha+'  '+file.name+'\n')
print('PASS deterministic source archive and',len(manifest),'file hashes:',sha)
