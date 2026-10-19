"""One-time, same-ship rename from %bitwarden to %urbitwarden.

The old agent is suspended and retained for rollback. Temporary on-init/on-load
hooks migrate state inside the ship, then both desks return to production source.
No vault state, keys, cookies or bearer tokens leave the ship.
"""
import argparse
import hashlib
import json
from pathlib import Path
import time

import deploy

OLD = 'bitwarden'
NEW = 'urbitwarden'
VAULT_INIT = '''  =/  egg  .^(egg-any:gall %gv /(scot %p our.bowl)/bitwarden/(scot %da now.bowl)/(scot %tas %$))
  ?>  ?=([%20 %live *] egg)
  (on-load +.old-state.egg)'''
CONNECT_MIGRATION = '''  =/  migrated  (load:ct old)
  =.  state.migrated
    =/  work  state.migrated
    =/  policies  ~(tap by integrations.work)
    |-  ^+  work
    ?~  policies  work
    =/  [id=@t policy=integration:c]  i.policies
    ?.  =(%bitwarden agent.policy)  $(policies t.policies)
    =/  kind
      ?:  =('bitwarden-' (crip (scag 10 (trip id))))  (crip (slag 10 (trip id)))
      id
    ?>  (~(has in (silt ~['cli' 'browser' 'desktop' 'mobile'])) kind)
    =/  new  (cat 3 'urbitwarden-' kind)
    ?>  !(~(has by clients.auth.work) new)
    =/  app  (~(got by clients.auth.work) id)
    =/  redirects  redirects.policy
    =/  redirect  redirect.app
    =?  redirects  =('browser' kind)
      (~(put in redirects) (cat 3 (crip (scag (sub (met 3 issuer.work) 8) (trip issuer.work))) '/apps/urbitwarden/sso-connector.html'))
    =?  redirect  =('browser' kind)
      (cat 3 (crip (scag (sub (met 3 issuer.work) 8) (trip issuer.work))) '/apps/urbitwarden/sso-connector.html')
    =.  auth.work  (rename-client:ca auth.work id new)
    =.  clients.auth.work
      (~(put by clients.auth.work) new app(id new, name (cat 3 'Urbitwarden ' ?:(=('browser' kind) 'browser extension' ?:(=('cli' kind) 'CLI' kind))), redirect redirect))
    =.  integrations.work
      (~(put by (~(del by integrations.work) id)) new policy(agent %urbitwarden, redirects redirects))
    $(policies t.policies)
'''


def migration_sources(vault, connect):
    old_init = '++  on-init\n  ^-  (quip card _this)\n  [route-cards this]'
    if vault.count(old_init) != 1:
        raise ValueError('Unexpected Urbitwarden init; review migration before applying')
    vault = vault.replace(old_init, '++  on-init\n  ^-  (quip card _this)\n' + VAULT_INIT)
    anchor = '  :_  this(world (load:ct old))'
    if connect.count(anchor) != 1 or '/+ ' not in connect:
        raise ValueError('Unexpected Connect load; review migration before applying')
    connect = connect.replace(anchor, CONNECT_MIGRATION + '  :_  this(world migrated)')
    return vault.encode(), connect.encode()


def prefix(ship):
    return (f'=/  m  (strand ,vase)  ;<  our=@p  bind:m  get-our  ?>  =(our {ship})  '
            ';<  now=@da  bind:m  get-time  ')


def source(control, ship, desk, relative):
    value = control.run(prefix(ship) + f'(pure:m !>(.^(@t %cx /{ship}/{desk}/(scot %da now)/{relative.replace(".", "/")})))')
    return value.to_bytes((value.bit_length() + 7) // 8, 'little')


def installed(control, ship):
    value = control.run(prefix(ship) + f'(pure:m !>(~(tap in .^((set desk) %cd /{ship}//(scot %da now)))))')
    return {deploy.cord(item) for item in deploy.noun_list(value)}


def write_sources(control, ship, desk, files, create=False):
    expressions = list(deploy.import_expressions(ship, desk, files))
    for expression in expressions if create else expressions[1:-1]:
        control.run(expression)


def migrate(control, release, ship, origin, apply=False):
    deploy.validate_ship(ship); deploy.validate_origin(origin)
    status = control.inspect(ship)
    desks = installed(control, ship)
    if not {'connect', OLD}.issubset(desks) or NEW in desks:
        raise ValueError('Migration requires existing %connect and %bitwarden, and no %urbitwarden desk')
    for route in status['routes']:
        if route['path'].startswith('/apps/urbitwarden'):
            raise ValueError('The destination route already exists')
        if route['path'] == '/apps/bitwarden' and route['app'] != OLD:
            raise ValueError('Legacy route belongs to another agent')
    connect = source(control, ship, 'connect', 'app/connect.hoon')
    files = release['desks'][NEW]
    vault = files['app/urbitwarden.hoon']
    temporary_vault, temporary_connect = migration_sources(vault.decode(), connect.decode())
    plan = {'ship': ship, 'from': OLD, 'to': NEW, 'origin': origin,
            'vaultSourceSHA256': hashlib.sha256(vault).hexdigest(),
            'connectSourceSHA256': hashlib.sha256(connect).hexdigest(),
            'connectProductionSourceChanged': False, 'applied': False}
    # The rename keeps the current versioned personal-vault shape unchanged.
    version = control.run(prefix(ship) + f'=/  egg  .^(egg-any:gall %gv /{ship}/bitwarden/(scot %da now)/(scot %tas %$))  ?>  ?=([%20 %live *] egg)  =/  saved  +.old-state.egg  (pure:m !>(-.q.saved))')
    if version != 2: raise ValueError('Upgrade the old vault to state version 2 before renaming it')
    if not apply: return plan
    # Stop the old writer before copying its saved state. Never nuke it.
    control.run(prefix(ship) + ';<  ~  bind:m  (poke-our %hood %kiln-suspend !>(%bitwarden))  (pure:m !>(~))')
    write_sources(control, ship, NEW, files | {'app/urbitwarden.hoon': temporary_vault}, create=True)
    # Check the renamed agent actually loaded the same encrypted account/content.
    # The comparison runs on the ship and returns only a boolean.
    # State equality uses each agent's saved vase type, so no fixed noun axes.
    compare = prefix(ship) + '''=/  before  .^(egg-any:gall %gv /(scot %p our)/bitwarden/(scot %da now)/(scot %tas %$))
      =/  after  .^(egg-any:gall %gv /(scot %p our)/urbitwarden/(scot %da now)/(scot %tas %$))
      ?>  &(?=([%20 %live *] before) ?=([%20 %live *] after))
      =/  old  +.old-state.before
      =/  new  +.old-state.after
      =/  query  (ream '(shax (jam [account ciphers folders attachments signing-key sessions serial revision]))')
      (pure:m !>(=(q:(slap (slop old !>(.)) query) q:(slap (slop new !>(.)) query))))'''
    for attempt in range(30):
        try:
            if control.run(compare) == 0: break
        except RuntimeError:
            pass
        time.sleep(1)
    else:
        raise RuntimeError('Renamed vault did not verify; old desk is retained, suspended. Do not enroll a new vault.')
    write_sources(control, ship, 'connect', {'app/connect.hoon': temporary_connect})
    # A successful scry confirms Connect's migrated agent is loaded before
    # restoring its original source; source import itself is asynchronous.
    verify = prefix(ship) + '''=/  egg  .^(egg-any:gall %gv /(scot %p our)/connect/(scot %da now)/(scot %tas %$))
      ?>  ?=([%20 %live *] egg)
      =/  saved  +.old-state.egg
      (pure:m !>(q:(slap (slop saved !>(.)) (ream '(levy ~(val by integrations) |=(p=[agent=@tas scopes=(set @t) redirects=(set @t)] !=(%bitwarden agent.p)))'))))'''
    for attempt in range(30):
        if control.run(verify) == 0: break
        time.sleep(1)
    else:
        raise RuntimeError('Connect migration did not verify; keep both desks and inspect before proceeding')
    write_sources(control, ship, NEW, {'app/urbitwarden.hoon': vault})
    write_sources(control, ship, 'connect', {'app/connect.hoon': connect})
    assert source(control, ship, NEW, 'app/urbitwarden.hoon') == vault
    assert source(control, ship, 'connect', 'app/connect.hoon') == connect
    plan['applied'] = True
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pier', required=True, type=Path)
    parser.add_argument('--ship', required=True)
    parser.add_argument('--origin', required=True)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    result = migrate(deploy.Control(args.pier), deploy.load_source(args.source), args.ship, args.origin, args.apply)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
