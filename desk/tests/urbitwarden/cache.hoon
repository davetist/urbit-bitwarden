::  Pure agent lifecycle tests: dummy responses only, no live credentials.
/+  *test, v=vault-json, va=vault-attachments
/=  vault  /app/urbitwarden
|%
++  test-public-jti-does-not-disclose-refresh-seed
  =/  seed=@  33
  =/  public  (slav %uv (token-id:v seed))
  ;:  weld
    (expect-eq !>(%.n) !>(=(seed public)))
    (expect-eq !>(%.n) !>(=((shas %refresh seed) (shas %refresh public))))
  ==
+$  session  [client=@t expires=@da access=@ux refresh=@ux consumed=(set @ux)]
+$  legacy-state
  $:  %1  account=json  signing-key=@  origin=@t
      sessions=(map @t session)  ciphers=(map @t json)  folders=(map @t json)
      serial=@ud  revision=@da
      cache=(map @t [old=@ux until=@da response=json])
      csrf=(map @ux [token=@ux expires=@da])
  ==
+$  state
  $:  %2  account=json  signing-key=@  origin=@t
      sessions=(map @t session)  ciphers=(map @t json)  folders=(map @t json)
      serial=@ud  revision=@da
      cache=(map @t [old=@ux until=@da response=json])
      csrf=(map @ux [token=@ux expires=@da])
      attachments=store:va  trash-next=(unit @da)
  ==
++  cache-cards
  |=  cards=(list card:agent:gall)
  ^+  cards
  (skim cards |=(c=card:agent:gall ?=([%pass [%cache-expiry *] *] c)))
++  clock-for
  |=  [ship=@p now=@da]
  =/  bowl=bowl:gall  *bowl:gall
  bowl(now now, our ship, src ship)
++  clock
  |=  now=@da
  (clock-for ~zod now)
++  fixture
  |=  [until=@da live=?]
  =/  old=legacy-state  *legacy-state
  =.  cache.old  (~(put by cache.old) 'sid' [0x0 until s+'dummy-response'])
  ?.  live  old
  old(sessions (~(put by sessions.old) 'sid' ['cli' until 0x1 0x2 ~]))
++  loaded
  |=  [now=@da until=@da live=?]
  =/  agent  ~(. vault (clock now))
  (on-load:agent !>((fixture until live)))
++  test-load-prunes-expired-response
  =/  result  (loaded ~2026.10.14..12.00.06 ~2026.10.14..12.00.05 &)
  =/  agent  +.result
  =/  saved  !<(state on-save:agent)
  ;:  weld
    (expect-eq !>(~) !>(cache.saved))
    (expect-eq !>(1) !>((lent ~(tap by sessions.saved))))
    (expect-eq !>(~) !>((cache-cards -.result)))
  ==
++  test-load-prunes-at-exact-deadline
  =/  result  (loaded ~2026.10.14..12.00.05 ~2026.10.14..12.00.05 &)
  =/  agent  +.result
  (expect-eq !>(~) !>(cache:!<(state on-save:agent)))
++  test-load-prunes-missing-session
  =/  result  (loaded ~2026.10.14..12.00.00 ~2026.10.14..12.00.05 |)
  =/  agent  +.result
  (expect-eq !>(~) !>(cache:!<(state on-save:agent)))
++  test-load-preserves-and-rearms-valid-response
  =/  until  ~2026.10.14..12.00.05
  =/  result  (loaded ~2026.10.14..12.00.00 until &)
  =/  agent  +.result
  =/  saved  !<(state on-save:agent)
  =/  expected=(list card:agent:gall)
    ~[[%pass /cache-expiry/sid/[(scot %da until)] %arvo %b %wait until]]
  ;:  weld
    (expect-eq !>(cache:(fixture until &)) !>(cache.saved))
    (expect-eq !>(expected) !>((cache-cards -.result)))
  ==
++  wake
  |=  [now=@da until=@da expected=@da]
  =/  result  (loaded ~2026.10.14..12.00.00 until &)
  =/  agent  ~(. +.result (clock now))
  (on-arvo:agent [/cache-expiry/sid/[(scot %da expected)] [%behn %wake ~]])
++  test-idle-wake-expires-only-response
  =/  result  (wake ~2026.10.14..12.00.05 ~2026.10.14..12.00.05 ~2026.10.14..12.00.05)
  =/  agent  +.result
  =/  saved  !<(state on-save:agent)
  ;:  weld
    (expect-eq !>(~) !>(cache.saved))
    (expect-eq !>(1) !>((lent ~(tap by sessions.saved))))
  ==
++  test-stale-wake-preserves-new-response
  =/  result  (wake ~2026.10.14..12.00.05 ~2026.10.14..12.00.08 ~2026.10.14..12.00.05)
  =/  agent  +.result
  (expect-eq !>(cache:(fixture ~2026.10.14..12.00.08 &)) !>(cache:!<(state on-save:agent)))
++  test-early-wake-preserves-response
  =/  result  (wake ~2026.10.14..12.00.03 ~2026.10.14..12.00.05 ~2026.10.14..12.00.05)
  =/  agent  +.result
  (expect-eq !>(cache:(fixture ~2026.10.14..12.00.05 &)) !>(cache:!<(state on-save:agent)))
++  test-legacy-load-revokes-credentials-preserves-vault
  =/  until  ~2026.10.14..12.00.05
  =/  old  (fixture until &)
  =.  old
    old(account (pairs:enjs:format ~[['key' s+'opaque-envelope'] ['creationDate' s+'created']]), signing-key 42, origin 'https://ship.example/apps/urbitwarden', ciphers (~(put by ciphers.old) 'item' s+'opaque-cipher'), folders (~(put by folders.old) 'folder' s+'opaque-folder'), serial 7, revision until, csrf (~(put by csrf.old) 0x1 [0x2 until]))
  =/  agent  ~(. vault (clock ~2026.10.14..12.00.00))
  =/  result  (on-load:agent !>([%0 +.old]))
  =/  next  +.result
  =/  saved  !<(state on-save:next)
  =/  revokes=(list card:agent:gall)
    (skim -.result |=(c=card:agent:gall ?=([%pass [%revoke ~] *] c)))
  ;:  weld
    (expect-eq !>((opt:v account.old 'key')) !>((opt:v account.saved 'key')))
    (expect-eq !>((opt:v account.old 'creationDate')) !>((opt:v account.saved 'creationDate')))
    (expect-eq !>(36) !>((met 3 (str:v (opt:v account.saved 'id')))))
    (expect-eq !>(ciphers.old) !>(ciphers.saved))
    (expect-eq !>(folders.old) !>(folders.saved))
    (expect-eq !>(~) !>(sessions.saved))
    (expect-eq !>(~) !>(cache.saved))
    (expect-eq !>(~) !>(csrf.saved))
    (expect-eq !>(~) !>(attachments.saved))
    (expect-eq !>(~) !>(trash-next.saved))
    (expect-eq !>(1) !>((lent revokes)))
    (expect-eq !>(~) !>((cache-cards -.result)))
  ==
++  test-upgrade-assigns-distinct-account-ids
  =/  now  ~2026.10.14..12.00.00
  =/  old  (fixture ~2026.10.14..12.00.05 &)
  =.  old  old(account (pairs:enjs:format ~[['email' s+'tester@example.invalid'] ['key' s+'wrapped']]))
  =/  first  ~(. vault (clock-for ~zod now))
  =/  second  ~(. vault (clock-for ~nec now))
  =/  result-first  (on-load:first !>([%1 +.old]))
  =/  result-second  (on-load:second !>([%1 +.old]))
  =/  agent-first  +.result-first
  =/  agent-second  +.result-second
  =/  saved-first  !<(state on-save:agent-first)
  =/  saved-second  !<(state on-save:agent-second)
  =/  id-first  (opt:v account.saved-first 'id')
  =/  id-second  (opt:v account.saved-second 'id')
  =/  reload-first  (on-load:first !>(saved-first))
  =/  reloaded-agent  +.reload-first
  =/  after-reload  !<(state on-save:reloaded-agent)
  ;:  weld
    (expect-eq !>(36) !>((met 3 (str:v id-first))))
    (expect-eq !>(36) !>((met 3 (str:v id-second))))
    (expect-eq !>(%.n) !>(=(id-first id-second)))
    (expect-eq !>(id-first) !>((opt:v account.after-reload 'id')))
    (expect-eq !>(~) !>(sessions.saved-first))
    (expect-eq !>((opt:v account.old 'key')) !>((opt:v account.saved-first 'key')))
  ==
++  test-current-state-upgrade-revokes-old-id-sessions
  =/  now  ~2026.10.14..12.00.00
  =/  old=state  *state
  =.  old
    old(account (pairs:enjs:format ~[['key' s+'wrapped']]), sessions (~(put by sessions.old) 'sid' ['desktop' (add now ~m1) 0x1 0x2 ~]), ciphers (~(put by ciphers.old) 'item' s+'opaque-cipher'))
  =/  agent  ~(. vault (clock now))
  =/  result  (on-load:agent !>(old))
  =/  loaded-agent  +.result
  =/  saved  !<(state on-save:loaded-agent)
  =/  revokes=(list card:agent:gall)
    (skim -.result |=(c=card:agent:gall ?=([%pass [%revoke ~] *] c)))
  ;:  weld
    (expect-eq !>(36) !>((met 3 (str:v (opt:v account.saved 'id')))))
    (expect-eq !>((opt:v account.old 'key')) !>((opt:v account.saved 'key')))
    (expect-eq !>(ciphers.old) !>(ciphers.saved))
    (expect-eq !>(~) !>(sessions.saved))
    (expect-eq !>(1) !>((lent revokes)))
  ==
--
