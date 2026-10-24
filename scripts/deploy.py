"""Install manifested source through a selected ship's stock local control socket.

This is an operator tool, not a service. It never boots a ship, changes ports,
reads owner credentials, or exports Gall state. Omit --apply to inspect a plan.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import ssl
import stat
import urllib.parse

from noun import atom, cell, jam

DESKS = {'connect': 'dependencies/urbit-connect/desk', 'urbitwarden': 'desk'}
ROUTES = {'/connect': 'connect', '/apps/connect': 'connect', '/apps/urbitwarden': 'urbitwarden'}
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_MANIFEST_ENTRIES = 4096
MAX_SOURCE_PATHS = 4096
MAX_SOURCE_FILES = 256
MAX_SOURCE_FILE_BYTES = 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 8 * 1024 * 1024


def no_symlinks(path):
    path = Path(os.path.abspath(path))
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Refusing symlink path')
    return path


def validate_ship(ship):
    if not re.fullmatch(r'~[a-z]{3}(?:[a-z]{3})?(?:-{1,2}[a-z]{6})*', ship):
        raise ValueError('Specify the exact ship name, including its leading ~')
    return ship


def validate_origin(origin):
    url = urllib.parse.urlsplit(origin)
    try: port = url.port
    except ValueError: raise ValueError('Invalid HTTPS origin port') from None
    if (url.scheme != 'https' or not url.hostname or url.username is not None or
            url.password is not None or url.path not in ('', '/') or url.query or
            url.fragment or port == 0 or any(c.isspace() for c in origin)):
        raise ValueError('Use an HTTPS origin without credentials, path, query or fragment')
    return urllib.parse.urlunsplit(('https', url.netloc.lower(), '', '', ''))


def runtime_binary(pier):
    """Resolve only the explicitly selected docked executable, never other data.

    `.run` may link inside or outside the pier. Backups materialize that one
    regular executable so a restored pier has no dependency on the old path.
    """
    try: binary = (Path(pier) / '.run').resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError('Selected pier has no resolvable docked runtime executable') from None
    if not stat.S_ISREG(binary.stat().st_mode) or not os.access(binary, os.X_OK):
        raise ValueError('Docked runtime must resolve to a regular executable file')
    return binary


def validate_pier(pier, require_runtime=True):
    pier = no_symlinks(pier)
    if not pier.is_dir() or not (pier / '.urb').is_dir():
        raise ValueError('Selected path is not a docked Urbit pier')
    no_symlinks(pier / '.urb')
    if require_runtime:
        runtime_binary(pier)
    if pier.stat().st_uid != os.getuid():
        raise ValueError('Run as the selected pier owner')
    return pier


def read_limited(path, limit, label):
    with path.open('rb') as stream: raw = stream.read(limit + 1)
    if len(raw) > limit: raise ValueError(label + ' byte limit exceeded')
    return raw


def source_paths(directory):
    pending = [directory]
    while pending:
        with os.scandir(pending.pop()) as children:
            for child in children:
                path = Path(child.path)
                yield path
                if child.is_dir(follow_symlinks=False): pending.append(path)


def load_source(root):
    # The explicitly selected source directory can be an alias (including
    # macOS /tmp). Once canonicalized, every manifest/desk descendant is still
    # checked without following symlinks outside that selected source tree.
    root = Path(root).expanduser().resolve(strict=True)
    manifest_path = no_symlinks(root / 'INTEGRATION-MANIFEST.json')
    if not manifest_path.is_file():
        raise ValueError('Extract a release source archive with INTEGRATION-MANIFEST.json first')
    raw_manifest = read_limited(manifest_path, MAX_MANIFEST_BYTES, 'Source manifest')
    manifest = json.loads(raw_manifest)
    if not isinstance(manifest, dict): raise ValueError('Invalid source manifest')
    if len(manifest) > MAX_MANIFEST_ENTRIES: raise ValueError('Source manifest entry limit exceeded')
    for name, digest in manifest.items():
        path = PurePosixPath(name)
        if (path.is_absolute() or '..' in path.parts or path.as_posix() != name or
                not re.fullmatch('[0-9a-f]{64}', str(digest))):
            raise ValueError('Invalid source manifest entry')
    desks = {}; path_count = 0; file_count = 0; total_bytes = 0
    for name, relative in DESKS.items():
        directory = no_symlinks(root / relative)
        if not directory.is_dir(): raise ValueError('Missing manifested desk: ' + name)
        entries = {}
        for path in source_paths(directory):
            path_count += 1
            if path_count > MAX_SOURCE_PATHS: raise ValueError('Source path limit exceeded')
            no_symlinks(path)
            if path.is_dir(): continue
            if not path.is_file(): raise ValueError('Non-regular source file')
            file_count += 1
            if file_count > MAX_SOURCE_FILES: raise ValueError('Source file limit exceeded')
            key = path.relative_to(root).as_posix()
            if key not in manifest: raise ValueError('Source file missing from manifest: ' + key)
            raw = read_limited(path, MAX_SOURCE_FILE_BYTES, 'Source file')
            total_bytes += len(raw)
            if total_bytes > MAX_SOURCE_TOTAL_BYTES: raise ValueError('Source total byte limit exceeded')
            if hashlib.sha256(raw).hexdigest() != manifest[key]:
                raise ValueError('Source hash mismatch: ' + key)
            relative_name = path.relative_to(directory).as_posix()
            if any(not re.fullmatch('[a-z0-9-]+', part) for part in relative_name.replace('.', '/').split('/')):
                raise ValueError('Unsupported Clay source path: ' + relative_name)
            entries[relative_name] = raw
        expected = {n[len(relative) + 1:] for n in manifest if n.startswith(relative + '/')}
        if set(entries) != expected: raise ValueError('Incomplete source manifest desk: ' + name)
        if 'app/' + name + '.hoon' not in entries or 'desk.bill' not in entries:
            raise ValueError('Missing desk entrypoint: ' + name)
        desks[name] = entries
    return {'desks': desks, 'manifestSHA256': hashlib.sha256(raw_manifest).hexdigest()}


def cue(data):
    """Decode the bounded local-control reply; no state or journal decoding."""
    bits = int.from_bytes(data, 'little'); position = 0; cache = {}
    def read(count):
        nonlocal position
        if count < 0 or position + count > len(data) * 8: raise ValueError('Truncated control reply')
        value = (bits >> position) & ((1 << count) - 1); position += count
        return value
    def rub():
        count = 0
        while read(1) == 0:
            count += 1
            if count > 32: raise ValueError('Oversized control atom')
        if not count: return 0
        size = (1 << (count - 1)) + read(count - 1)
        return read(size)
    def decode(depth=0):
        if depth > 400: raise ValueError('Control reply too deep')
        start = position
        if read(1) == 0: value = rub()
        elif read(1) == 0: value = (decode(depth + 1), decode(depth + 1))
        else:
            reference = rub()
            if reference not in cache: raise ValueError('Invalid control reference')
            return cache[reference]
        cache[start] = value
        return value
    return decode()


def control_result(data):
    result = cue(data)
    for expected in (0, atom('avow'), 0, atom('noun')):
        if not isinstance(result, tuple) or result[0] != expected:
            raise RuntimeError('Native control request failed; no private diagnostic was exported')
        result = result[1]
    return result


def cord(value):
    if not isinstance(value, int): raise ValueError('Expected native text atom')
    return value.to_bytes((value.bit_length() + 7) // 8, 'little').decode('utf-8')


def noun_list(value):
    result = []
    while value != 0:
        if not isinstance(value, tuple): raise ValueError('Malformed native list')
        head, value = value; result.append(head)
    return result


class Control:
    def __init__(self, pier, require_runtime=True):
        self.pier = validate_pier(pier, require_runtime=require_runtime)
        self.socket = no_symlinks(self.pier / '.urb/conn.sock')
        if not self.socket.exists() or not stat.S_ISSOCK(self.socket.stat().st_mode):
            raise ValueError('Selected pier has no running stock local control socket')

    def run(self, expression, max_reply_bytes=4 * 1024 * 1024):
        payload = jam(cell(0, 'fyrd', 'base', 'khan-eval', 'noun', 'ted-eval', expression))
        return control_result(self.request(payload, max_reply_bytes))

    def peek(self, desk, path, max_reply_bytes=4 * 1024 * 1024):
        spur = 0
        for part in reversed(path): spur = cell(part, spur)
        payload = jam(cell(0, 'peek', 1, 'once', 'gx', desk, spur))
        return cue(self.request(payload, max_reply_bytes))

    def request(self, payload, max_reply_bytes):
        def receive(connection, size):
            data = bytearray()
            while len(data) < size:
                part = connection.recv(size - len(data))
                if not part: raise RuntimeError('Native control socket closed early')
                data.extend(part)
            return bytes(data)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(240); connection.connect(str(self.socket))
            connection.sendall(b'\0' + len(payload).to_bytes(4, 'little') + payload)
            header = receive(connection, 5)
            size = int.from_bytes(header[1:], 'little')
            if header[0] != 0 or (max_reply_bytes is not None and size > max_reply_bytes):
                raise RuntimeError('Unexpected native control reply frame')
            return receive(connection, size)

    def inspect(self, ship):
        validate_ship(ship)
        # Read only identity, desk names and route owners. No credential state.
        expression = (
            '=/  m  (strand ,vase)  ;<  our=@p  bind:m  get-our  '
            f'?>  =(our {ship})  ;<  now=@da  bind:m  get-time  '
            '=/  desks  .^((set desk) %cd /(scot %p our)//(scot %da now))  '
            '=/  bound  .^((list [binding=binding:eyre duct=duct action=action:eyre]) %e /(scot %p our)/bindings/(scot %da now))  '
            '=/  routes  (turn bound |=(entry=[binding=binding:eyre duct=duct action=action:eyre] [binding.entry action.entry]))  '
            '(pure:m !>([(scot %p our) (~(has in desks) %connect) (~(has in desks) %urbitwarden) (~(has in desks) %bitwarden) routes]))')
        raw = self.run(expression)
        ship_atom, rest = raw; has_connect, rest = rest; has_urbitwarden, rest = rest; has_legacy, bindings = rest
        routes = []
        for binding, action in noun_list(bindings):
            site, path = binding
            routes.append({'site': None if site == 0 else cord(site[1]),
                           'path': '/' + '/'.join(cord(part) for part in noun_list(path)),
                           'app': cord(action[1]) if action[0] == atom('app') else None})
        return {'ship': cord(ship_atom), 'legacyDesk': has_legacy == 0,
                'desks': [name for name, found in [('connect', has_connect), ('urbitwarden', has_urbitwarden)] if found == 0],
                'routes': routes}

    def inert_desk(self, ship, desk):
        """Accept only a stopped Clay name with no app files or Gall state.

        A removed desk may still appear in Clay's desk set. Its sole remaining
        file may be the mandatory Kelvin marker. Never classify an installed or
        suspended vault with application files as an empty historical name.
        """
        validate_ship(ship)
        if desk not in (*DESKS, 'bitwarden'):
            raise ValueError('Unexpected selected desk')
        prefix = '=/  m  (strand ,vase)  ;<  now=@da  bind:m  get-time  '
        files = self.run(prefix + f'=/  f  .^((list path) %ct /{ship}/{desk}/(scot %da now))  '
                         '(pure:m !>((levy f |=(p=path =(p /sys/kelvin)))))') == 0
        stopped = self.run(prefix + f'=/  t  (~(got by .^(rock:tire:clay %cx /{ship}//(scot %da now)/tire)) %{desk})  '
                           '(pure:m !>(=(%dead zest.t)))') == 0
        if not (files and stopped):
            return False
        # A missing Gall state scry is expected for a removed agent. Any live
        # state, even on a stopped desk, rules out re-seeding this name.
        try:
            self.run(prefix + f'=/  egg  .^(egg-any:gall %gv /{ship}/{desk}/(scot %da now)/(scot %tas %$))  '
                     '(pure:m !>(~))')
        except RuntimeError:
            # Distinguish a missing target from a broken Gall scry/control path.
            self.run(prefix + f'=/  egg  .^(egg-any:gall %gv /{ship}/hood/(scot %da now)/(scot %tas %$))  '
                     '(pure:m !>(~))')
            return True
        return False


def check_routes(routes, origin):
    host = urllib.parse.urlsplit(origin).hostname
    for binding in routes:
        if binding['site'] not in (None, host): continue
        for path, owner in ROUTES.items():
            # Child routes would shadow part of the new application as well.
            if (binding['path'] == path or binding['path'].startswith(path + '/')) and binding['app'] != owner:
                raise ValueError('Existing route belongs to another handler: ' + binding['path'])


def check_target(status, ship, origin, update_existing):
    if status['ship'] != ship: raise ValueError('Selected ship identity does not match the live pier')
    check_routes(status['routes'], origin)
    if status['desks'] and not update_existing:
        raise ValueError('Existing selected desk(s); review and pass --update-existing: ' + ', '.join(status['desks']))


def import_expressions(ship, desk, entries, *, target=None, install=True, reseed=False):
    validate_ship(ship)
    if desk not in DESKS: raise ValueError('Unexpected selected desk')
    target = desk if target is None else target
    if target not in (desk, desk + '-alpha'):
        raise ValueError('Unexpected destination desk')
    desk = target
    # Start a new history with only the packaged seed marks, as |new-desk does.
    # Merging %base also copies its apps, kernel, tools and history into the app.
    seed_names = ('mar/noun.hoon', 'mar/hoon.hoon', 'mar/txt.hoon',
                  'mar/kelvin.hoon', 'sys.kelvin')
    seed_rows = []
    for name in seed_names:
        if name not in entries:
            raise ValueError('Missing minimal desk seed file: ' + name)
        digits = format(int.from_bytes(entries[name], 'little'), 'x')
        value = '0x' + '.'.join(reversed([digits[max(0, end - 4):end] for end in range(len(digits), 0, -4)]))
        mark = name.rsplit('.', 1)[-1]
        if mark == 'kelvin':
            value = f'(cord-to-waft:clay `@t`{value})'
        seed_rows.append(f'[/{name.replace(".", "/")} %{mark} {value}]')
    seed = ' '.join(seed_rows)
    guard = '' if reseed else f'?:  (~(has in .^((set desk) %cd /{ship}//(scot %da now))) %{desk})  (pure:m !>(~))  '
    yield (f'=/  m  (strand ,vase)  ;<  now=@da  bind:m  get-time  '
           + guard +
           f'=/  seed=(map path page:clay)  (~(gas by *(map path page:clay)) ~[{seed}])  '
           f';<  ~  bind:m  (send-raw-card [%pass /create %arvo (new-desk:cloy %{desk} ~ seed)])  '
           ';<  ~  bind:m  (sleep ~s1)  (pure:m !>(~))')
    for hoon_phase in (True, False):
        prefix = '=/  m  (strand ,vase)  ;<  now=@da  bind:m  get-time  '
        changes = []
        for index, (name, raw) in enumerate(sorted(entries.items())):
            if name.endswith('.hoon') != hoon_phase: continue
            mark = name.rsplit('.', 1)[-1]
            digits = format(int.from_bytes(raw, 'little'), 'x')
            value = '0x' + '.'.join(reversed([digits[max(0, end - 4):end] for end in range(len(digits), 0, -4)]))
            length = format(len(raw), ',').replace(',', '.')
            prefix += f'=/  tube{index}=tube:clay  .^(tube:clay %cc /{ship}/{desk}/(scot %da now)/mime/{mark})  '
            prefix += f'=/  val{index}=vase  (tube{index} !>(`mime`[/text/plain [{length} {value}]]))  '
            changes.append(f'[/{name.replace(".", "/")} %ins %{mark} val{index}]')
        if changes:
            yield (prefix + f';<  ~  bind:m  (send-raw-card [%pass /import %arvo %c %info [%{desk} %.y ~[' +
                   ' '.join(changes) + ']]])  ;<  ~  bind:m  (sleep ~s1)  (pure:m !>(~))')
    if install:
        yield (f'=/  m  (strand ,vase)  ;<  ~  bind:m  (poke-our %hood %kiln-install !>([%{desk} {ship} %{desk}]))  '
               ';<  ~  bind:m  (sleep ~s1)  (pure:m !>(~))')


def deploy(control, release, ship, origin, apply=False, update_existing=False, reuse_empty_history=False):
    ship = validate_ship(ship); origin = validate_origin(origin)
    status = control.inspect(ship)
    selected = status['desks'] + (['bitwarden'] if status.get('legacyDesk') else [])
    inert = {name for name in selected if reuse_empty_history and control.inert_desk(ship, name)}
    if status.get('legacyDesk') and 'urbitwarden' not in status['desks'] and 'bitwarden' not in inert:
        raise ValueError('Existing %bitwarden vault: use scripts/migrate_urbitwarden.py to preserve its state and Connect grants')
    check_target(status | {'desks': [name for name in status['desks'] if name not in inert]}, ship, origin, update_existing)
    result = {'ship': ship, 'origin': origin, 'urbitwardenURL': origin + '/apps/urbitwarden',
              'manifestSHA256': release['manifestSHA256'], 'desks': list(DESKS),
              'existingDesks': status['desks'], 'inertHistoricalDesks': sorted(inert), 'applied': apply}
    if apply:
        for desk in DESKS:
            for expression in import_expressions(ship, desk, release['desks'][desk], reseed=desk in inert): control.run(expression)
    return result


def tls_expression(cert, key):
    # Validate key/certificate compatibility with Python's existing TLS support;
    # never print the key, include it in argv, or persist an extra copy.
    cert = no_symlinks(cert); key = no_symlinks(key)
    if key.stat().st_mode & 0o077: raise ValueError('TLS key must be readable only by its owner (mode 600)')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try: context.load_cert_chain(cert, key, password='')
    except (ssl.SSLError, OSError): raise ValueError('TLS certificate and key do not form a usable pair') from None
    def wain(path):
        lines = path.read_text().splitlines()
        if not lines or any(not re.fullmatch('[A-Za-z0-9+/= -]+', line) for line in lines):
            raise ValueError('Use an unencrypted PEM certificate chain and PEM key')
        return '~[' + ' '.join("'" + line + "'" for line in lines) + ']'
    return ('=/  m  (strand ,vase)  ;<  ~  bind:m  (send-raw-card [%pass /tls %arvo %e %rule %cert [~ ' +
            wain(key) + ' ' + wain(cert) + ']])  ;<  ~  bind:m  (sleep ~s1)  (pure:m !>(~))')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pier', required=True, type=Path)
    parser.add_argument('--ship', required=True)
    parser.add_argument('--origin', required=True, help='HTTPS origin; the client URL adds /apps/urbitwarden')
    parser.add_argument('--source', type=Path, help='Extracted source archive containing INTEGRATION-MANIFEST.json')
    parser.add_argument('--tls-only', action='store_true', help='Inspect or replace only the chosen Eyre certificate; do not import desks')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--update-existing', action='store_true', help='Authorize updating the selected Connect and Urbitwarden desks')
    parser.add_argument('--reuse-empty-history', action='store_true', help='Re-seed only stopped historical desk names with no application files or Gall state')
    parser.add_argument('--cert', type=Path); parser.add_argument('--key', type=Path)
    parser.add_argument('--apply-tls', action='store_true', help='Explicitly replace Eyre TLS with the supplied certificate/key')
    args = parser.parse_args()
    if bool(args.cert) != bool(args.key) or args.apply_tls and not (args.apply and args.cert):
        parser.error('Supply --cert and --key together; --apply-tls also requires --apply')
    if args.tls_only and not args.cert or not args.tls_only and not args.source:
        parser.error('Normal installation requires --source; --tls-only requires --cert and --key')
    if args.tls_only and args.apply and not args.apply_tls:
        parser.error('Applying --tls-only requires --apply-tls')
    try:
        release = None if args.tls_only else load_source(args.source)
        validate_ship(args.ship); validate_origin(args.origin)
        tls = tls_expression(args.cert, args.key) if args.cert else None
        control = Control(args.pier)
        if args.tls_only:
            status = control.inspect(args.ship)
            if status['ship'] != args.ship: raise ValueError('Selected ship identity does not match the live pier')
            result = {'ship': args.ship, 'origin': validate_origin(args.origin), 'desks': [], 'applied': args.apply}
        else:
            result = deploy(control, release, args.ship, args.origin, args.apply, args.update_existing, args.reuse_empty_history)
        if args.apply_tls: control.run(tls)
        result['tlsReplaced'] = args.apply_tls
        print(json.dumps(result, indent=2))
        if args.apply:
            print('TLS replacement requested. Verify HTTPS with normal certificate validation.' if args.tls_only
                  else 'Source imports requested. Verify the owner page and client workflow before using the vault.')
        else: print('Plan only. No desks, ports, certificates or authorization settings changed.')
    except (OSError, ValueError, RuntimeError) as error:
        raise SystemExit(str(error)) from None


if __name__ == '__main__': main()
