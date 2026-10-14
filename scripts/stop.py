"""Stop the selected owned process, verifying identity and actual termination."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from fixture import WORK, owned, running_process


def wait_stopped(timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if running_process() is None: return True
        time.sleep(.1)
    return running_process() is None


def stop(timeout=30):
    owned()
    identity = running_process()
    control_socket = WORK / 'pier/.urb/conn.sock'
    if identity is None:
        if control_socket.exists():
            raise RuntimeError('Control socket has no verified owned process; preserve and investigate')
    else:
        if control_socket.exists():
            expr = '=/  m  (strand ,vase)  ;<  ~  bind:m  (poke-our %hood %drum-exit !>(~))  (pure:m !>(~))'
            try:
                result = subprocess.run([sys.executable, str(Path(__file__).with_name('control.py')), '--khan', expr],
                                        capture_output=True, text=True, timeout=max(.2, min(timeout, 10)))
                if result.returncode:
                    print('Fixture control shutdown failed; verifying process and using SIGTERM.', file=sys.stderr)
            except (OSError, subprocess.TimeoutExpired):
                print('Fixture control shutdown unavailable; verifying process and using SIGTERM.', file=sys.stderr)
            stopped = wait_stopped(timeout)
        else:
            print('Fixture control socket missing; terminating the verified owned process.', file=sys.stderr)
            stopped = False
        if not stopped:
            current = running_process()
            if current is not None: os.kill(current['pid'], signal.SIGTERM)
            if not wait_stopped(5):
                current = running_process()
                if current is not None: os.kill(current['pid'], signal.SIGKILL)
                if not wait_stopped(5): raise RuntimeError('Owned fixture process did not terminate')
        control_socket.unlink(missing_ok=True)
    for name in ('runtime.pid', 'runtime-process.json'): (WORK / name).unlink(missing_ok=True)
    print('Bitwarden desk fixture stopped; process termination verified.')


if __name__ == '__main__': stop()
