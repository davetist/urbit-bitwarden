"""Start the selected owned fixture and wait for its control and HTTP services."""
import json
import os
import socket
import subprocess
import time
import http.client
from fixture import ROOT, WORK, HTTP_PORT, HTTPS_PORT, AMES_PORT, owned, process_identity, running_process


def ready(pier):
    if not (pier / '.urb/conn.sock').exists():
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
            control.settimeout(.2)
            control.connect(str(pier / '.urb/conn.sock'))
        connection = http.client.HTTPConnection('127.0.0.1', HTTP_PORT, timeout=.5)
        try:
            connection.request('GET', '/')
            return 200 <= connection.getresponse().status < 600
        finally:
            connection.close()
    except (OSError, http.client.HTTPException):
        return False



def check_ports(ports):
    listeners = []
    try:
        for port, kind in ports:
            listener = socket.socket(socket.AF_INET, kind); listeners.append(listener)
            if kind == socket.SOCK_STREAM:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('127.0.0.1', port))
            if kind == socket.SOCK_STREAM:
                listener.listen(1)  # Still reject an existing listener, not TIME_WAIT.
    finally:
        for listener in listeners: listener.close()


def start(timeout=300):
    owned(create=True)
    pier = WORK / 'pier'
    if running_process() is not None:
        raise RuntimeError('Bitwarden desk fixture is already running')
    if (pier / '.urb/conn.sock').exists():
        raise RuntimeError('Fixture has a control socket; inspect it before restarting')
    # Catch conflicts before creating a process that cannot become ready.
    check_ports(((HTTP_PORT, socket.SOCK_STREAM), (HTTPS_PORT, socket.SOCK_STREAM), (AMES_PORT, socket.SOCK_DGRAM)))
    vere = ROOT / '.work/toolchains/vere-4.6/vere-v4.6-macos-aarch64'
    pill = ROOT / '.work/toolchains/urbit-v4.6.pill'
    args = [str(vere), '-b', '127.0.0.1', '--http-port', str(HTTP_PORT), '--https-port', str(HTTPS_PORT), '-p', str(AMES_PORT), '-t']
    args += [str(pier)] if (pier / '.urb').exists() else ['-B', str(pill), '-F', 'zod', '-c', str(pier)]
    with (WORK / 'runtime.log').open('ab') as out:
        os.chmod(out.name, 0o600)
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=out, stderr=out, start_new_session=True)
    try:
        identity = process_identity(proc.pid)
        if identity is None: raise RuntimeError('Fixture exited during launch')
        for name, value in (('runtime.pid', str(proc.pid)), ('runtime-process.json', json.dumps(identity))):
            path = WORK / name; path.write_text(value); path.chmod(0o600)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError('Fixture exited before readiness; inspect private runtime.log')
            if ready(pier):
                settled = process_identity(proc.pid)
                if settled is None or settled['started'] != identity['started']:
                    raise RuntimeError('Fixture exited during readiness')
                (WORK / 'runtime-process.json').write_text(json.dumps(settled))
                print('Bitwarden desk fixture ready; PID', proc.pid)
                return proc.pid
            time.sleep(.1)
        raise RuntimeError('Fixture did not become ready; inspect private runtime.log')
    except BaseException:
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=5)
        for name in ('runtime.pid', 'runtime-process.json'): (WORK / name).unlink(missing_ok=True)
        (pier / '.urb/conn.sock').unlink(missing_ok=True)
        raise


if __name__ == '__main__': start()
