"""Native agent lifecycle tests using dummy responses, never live state exports."""
import json
import re
import subprocess
import sys
from pathlib import Path
from fixture import NAME, WORK, EVIDENCE, owned


def main():
    if NAME != 'review-fixes':
        raise SystemExit('Use CONNECT_BW_FIXTURE=review-fixes; preserve the demo fixture.')
    owned()
    log = WORK / 'runtime.log'
    start = log.stat().st_size
    expression = ('=/  m  (strand ,vase)  ;<  now=@da  bind:m  get-time  '
                  ';<  result=thread-result  bind:m  '
                  '(await-thread %test !>([~ /~zod/bitwarden/(scot %da now)/tests/bitwarden/cache]))  '
                  '?>  ?=(%& -.result)  (pure:m p.result)')
    result = subprocess.run([sys.executable, str(Path(__file__).with_name('control.py')), '--khan', expression],
                            capture_output=True, text=True, timeout=180)
    with log.open('rb') as source:
        source.seek(start)
        output = source.read().decode(errors='replace')
    passed = re.findall(r'OK\s+(/tests/bitwarden/cache/[^\s]+)', output)
    for line in output.splitlines():
        if '/tests/bitwarden/cache/' in line or line.startswith(('expected', 'actual', 'syntax error', '-find', '-nest')):
            print(line)
    if result.returncode or result.stdout.strip() != '[0 %avow 0 %noun 0]' or len(passed) != 7:
        raise SystemExit('Native cache lifecycle tests failed or did not execute all 7 cases.')
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / 'cache-lifecycle.json').write_text(json.dumps({
        'execution': 'stock Vere Hoon test thread; instantiated agent with inert dummy responses',
        'passed': passed, 'count': len(passed), 'live_credential_state_inspected': False,
        'journal_inspected': False,
    }, indent=2) + '\n')
    print('PASS 7 native cache lifecycle tests; no live credential or journal inspection')


if __name__ == '__main__': main()
