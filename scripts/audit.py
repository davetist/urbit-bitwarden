"""Prepare and run the synthetic journal audit without rendering secret nouns."""
from pathlib import Path
import subprocess,sys,venv
from fixture import ROOT, WORK, EVIDENCE
SCRIPTS=Path(__file__).resolve().parent
for name in ['fixture.json','enrollment-plaintexts.json','browser-traffic.json','owner.json']:
 if not (WORK/name).exists():raise SystemExit('Missing private '+name+'; complete browser enrollment and client acceptance first.')
python=WORK/'python/bin/python'
if not python.exists():venv.EnvBuilder(with_pip=True).create(WORK/'python')
subprocess.run([str(python),'-m','pip','install','lmdb==1.7.5'],check=True)
# Produce a fresh issued token for the independent signature and positive-control checks.
subprocess.run([sys.executable,str(SCRIPTS/'probe_sso.py')],check=True)
for agent in ['connect','bitwarden']:
 expr=f'=/  m  (strand ,vase)  ;<  now=@da  bind:m  get-time  =/  egg  .^(egg-any:gall %gv /~zod/{agent}/(scot %da now)/(scot %tas %$))  ?>  ?=([%20 %live *] egg)  =/  saved=vase  +.old-state.egg  (pure:m !>(q.saved))'
 subprocess.run([sys.executable,str(SCRIPTS/'control.py'),'--save-jam',agent,'--khan',expr],check=True)
subprocess.run([str(python),str(SCRIPTS/'test_native_crypto.py')],check=True)
subprocess.run([str(python),str(SCRIPTS/'check_history.py')],check=True)
