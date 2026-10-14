::  Urbit-native Bitwarden backend. Connect remains the authorization authority.
/-  c=connect
/+  default-agent, server, v=vault-json, ce=connect-entry, assets=vault-assets
|%
+$  card  card:agent:gall
+$  session  [client=@t expires=@da access=@ux refresh=@ux consumed=(set @ux)]
+$  vault-state
  $:  %0  account=json  signing-key=@  origin=@t
      sessions=(map @t session)  ciphers=(map @t json)  folders=(map @t json)
      serial=@ud  revision=@da
      cache=(map @t [old=@ux until=@da response=json])
      csrf=(map @ux [token=@ux expires=@da])
  ==
++  revoke-card
  |=  [ship=@p sid=@t]
  ^-  card
  [%pass /revoke %agent [ship %connect] %poke %connect-revoke !>(`revoke-request:c`[%bitwarden sid])]
++  cache-wait
  |=  [sid=@t until=@da]
  ^-  card
  [%pass /cache-expiry/[sid]/[(scot %da until)] %arvo %b %wait until]
++  unavailable
  |=  rid=@ta
  ^-  (list card)
  (give-simple-payload:app:server rid [[503 ~[['content-type' 'application/json'] ['cache-control' 'no-store']]] `(as-octs:mimes:html '{"error":"temporarily_unavailable"}')])
--
^-  agent:gall
=|  state=vault-state
=|  pending=(map @t [rid=@ta client=@t device=@t until=@da])
=*  account  account.state
=*  sessions  sessions.state
=*  ciphers  ciphers.state
=*  folders  folders.state
|_  =bowl:gall
+*  this  .
    def  ~(. (default-agent this %|) bowl)
++  on-init
  ^-  (quip card _this)
  :_  this
  :~  [%pass /bind/api %arvo %e %connect `/api %bitwarden]
      [%pass /bind/identity %arvo %e %connect `/identity %bitwarden]
      [%pass /bind/root %arvo %e %connect `/ %bitwarden]
  ==
++  on-save  !>(state)
++  on-load
  |=  old=vase
  ^-  (quip card _this)
  =.  state  !<(vault-state old)
  =.  pending  ~
  ::  Keep restart retries only while their original grace window is live.
  =.  cache.state
    (malt (skim ~(tap by cache.state) |=([p=@t q=[old=@ux until=@da response=json]] &((~(has by sessions) p) (lth now.bowl until.q)))))
  =/  timers=(list card)  (turn ~(tap by cache.state) |=([p=@t q=[old=@ux until=@da response=json]] (cache-wait p until.q)))
  =/  completed=(list card)
    %-  zing
    %+  turn  ~(val by sup.bowl)
    |=  [ship=@p p=path]
    ^-  (list card)
    ?.  ?=([%http-response @ ~] p)  ~
    (unavailable i.t.p)
  [(weld timers completed) this]
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  |^
  ?:  =(%json mark)
    ?>  &(=(src.bowl our.bowl) =(sap.bowl /gall/connect))
    =/  data=json  !<(json vase)
    =/  request  (str:v (get:v data 'request'))
    =/  found  (~(get by pending) request)
    ?~  found
      ?.  =((get:v data 'status') n+'200')  `this
      [~[(revoke-card our.bowl (str:v (get:v (get:v data 'grant') 'sessionId')))] this]
    =.  pending  (~(del by pending) request)
    =/  rid  rid.u.found
    ?.  =((get:v data 'status') n+'200')  (reply rid 400 invalid)
    ?.  (lth now.bowl until.u.found)
      [[(revoke-card our.bowl (str:v (get:v (get:v data 'grant') 'sessionId'))) (unavailable rid)] this]
    =/  sid  (str:v (get:v (get:v data 'grant') 'sessionId'))
    ?:  =(~ (grant sid))
      =/  response  (reply rid 400 invalid)
      [[(revoke-card our.bowl sid) -.response] +.response]
    =.  sessions  (~(put by sessions) sid [client.u.found now.bowl 0x0 0x0 ~])
    (issue rid sid device.u.found)
  ?.  =(%handle-http-request mark)  (on-poke:def mark vase)
  =/  [rid=@ta req=inbound-request:eyre]  !<([@ta inbound-request:eyre] vase)
  ?>  (http-watch:ce sup.bowl src.bowl /http-response/[rid])
  ?:  &(?=(^ body.request.req) (gth p.u.body.request.req 262.144))  (reply rid 413 ~)
  =/  attempt  (mule |.(!>((handle rid req))))
  ?:  ?=(%| -.attempt)  (reply rid 400 invalid)
  !<((quip card _this) p.attempt)
  ++  grant
    |=  sid=@t
    ^-  json
    =/  value  .^(json %gx /(scot %p our.bowl)/connect/(scot %da now.bowl)/integration/bitwarden/[sid]/json)
    ?~  value  ~
    =/  scopes  (get:v value 'scopes')
    ?>  ?=([%a *] scopes)
    ?.  &((lien p.scopes |=(j=json =(j s+'api'))) (lien p.scopes |=(j=json =(j s+'offline_access'))))  ~
    value
  ++  invalid  (pairs:enjs:format ~[['error' s+'invalid_grant'] ['error_description' s+'Authorization is invalid or expired']])
  ++  reply
    |=  [rid=@ta status=@ud body=json]
    ^-  (quip card _this)
    =/  txt  (en:json:html body)
    (raw rid status 'application/json; charset=utf-8' txt)
  ++  raw
    |=  [rid=@ta status=@ud mime=@t txt=@t]
    ^-  (quip card _this)
    :_  this
    %+  give-simple-payload:app:server  rid
    :-  [status ~[['content-type' mime] ['cache-control' 'no-store'] ['x-content-type-options' 'nosniff'] ['referrer-policy' 'no-referrer'] ['x-frame-options' 'DENY'] ['content-security-policy' (crip "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")]]]
    `[p=(met 3 txt) q=txt]
  ++  redirect
    |=  [rid=@ta to=@t]
    ^-  (quip card _this)
    :_  this
    (give-simple-payload:app:server rid [[302 ~[['location' to] ['cache-control' 'no-store'] ['referrer-policy' 'no-referrer']]] ~])
  ++  form
    |=  raw=@t
    ^-  (map @t @t)
    =/  line  (parse-request-line:server (cat 3 '/?' raw))
    =/  out  *(map @t @t)
    =/  args  args.line
    |-  ^+  out
    ?~  args  out
    ?>  !(~(has by out) key.i.args)
    $(args t.args, out (~(put by out) key.i.args value.i.args))
  ++  issue
    |=  [rid=@ta sid=@t device=@t]
    ^-  (quip card _this)
    =.  sessions  (malt (skim ~(tap by sessions) |=([p=@t q=session] !=(~ (grant p)))))
    =.  cache.state  (malt (skim ~(tap by cache.state) |=([p=@t q=[old=@ux until=@da response=json]] &((~(has by sessions) p) (lth now.bowl until.q)))))
    =/  value  (~(got by sessions) sid)
    =/  expiry  (add now.bowl ~s60)
    =/  claims
      %-  pairs:enjs:format
      :~  ['sub' s+'00000000-0000-4000-8000-000000000001']
          ['email' (opt:v account 'email')]  ['email_verified' b+%.y]
          ['name' s+'Urbit vault']  ['premium' b+%.n]
          ['iss' s+(cat 3 origin.state '/identity')]  ['aud' s+'api']
          ['exp' (sect:enjs:format expiry)]  ['nbf' (sect:enjs:format now.bowl)]
          ['iat' (sect:enjs:format now.bowl)]  ['amr' a+~[s+'Application']]
          ['scope' a+~[s+'api' s+'offline_access']]  ['device' s+device]
          ['sstamp' s+'connect-sso-v1']  ['jti' s+(scot %uv eny.bowl)]
          ['sid' s+sid]  ['client_id' s+client.value]
      ==
    =/  token  (jwt:v claims signing-key.state)
    =/  refresh  (b64:v (scot %ux (shas %refresh eny.bowl)))
    =/  prior  refresh.value
    =.  value  value(expires expiry, access (shax token), refresh (shax refresh))
    =?  consumed.value  !=(0 prior)  (~(put in consumed.value) prior)
    =.  sessions  (~(put by sessions) sid value)
    =/  response
      %-  pairs:enjs:format
      :~  ['access_token' s+token]  ['refresh_token' s+refresh]
          ['expires_in' n+'60']  ['token_type' s+'Bearer']
          ['scope' s+'api offline_access']  ['Key' (opt:v account 'key')]
          ['PrivateKey' (opt:v account 'privateKey')]  ['AccountKeys' account-keys]
          ['Kdf' n+'0']  ['KdfIterations' n+'600000']
          ['KdfMemory' ~]  ['KdfParallelism' ~]
          ['ForcePasswordReset' b+%.n]  ['MasterPasswordPolicy' ~]
          ['UserDecryptionOptions' (pairs:enjs:format ~[['HasMasterPassword' b+%.y] ['MasterPasswordUnlock' unlock-data] ['Object' s+'userDecryptionOptions']])]
      ==
    =/  until  (add now.bowl ~s5)
    =.  cache.state  (~(put by cache.state) sid [prior until response])
    =/  result  (reply rid 200 response)
    [[(cache-wait sid until) -.result] +.result]
  ++  token
    |=  [rid=@ta req=inbound-request:eyre]
    ^-  (quip card _this)
    ?.  =(method.request.req %'POST')  (reply rid 405 ~)
    =/  content-type  (fall (get-header:http 'content-type' header-list.request.req) '')
    ?.  |(=(content-type 'application/x-www-form-urlencoded') =(content-type 'application/x-www-form-urlencoded; charset=utf-8'))  (reply rid 400 invalid)
    =/  fields  (form ?~(body.request.req '' q.u.body.request.req))
    =/  kind  (~(gut by fields) 'grant_type' '')
    =/  client  (~(gut by fields) 'client_id' '')
    ?.  |(=(client 'cli') =(client 'browser'))  (reply rid 400 invalid)
    =/  allowed
      ?:  =(kind 'authorization_code')  (silt ~['scope' 'grant_type' 'client_id' 'code' 'code_verifier' 'redirect_uri' 'deviceType' 'deviceIdentifier' 'deviceName' 'devicePushToken' 'twoFactorRemember'])
      (silt ~['grant_type' 'client_id' 'refresh_token'])
    ?>  (levy ~(tap in ~(key by fields)) |=(key=@t (~(has in allowed) key)))
    ?:  =(kind 'authorization_code')
      ?>  =('api offline_access' (~(gut by fields) 'scope' 'api offline_access'))
      ?:  =(account ~)  (reply rid 400 invalid)
      ?:  (gte (lent ~(tap by pending)) 32)  (reply rid 429 ~)
      =/  request  (scot %uv (shas %exchange eny.bowl))
      =/  data=exchange-request:c  [request client (~(got by fields) 'code') (~(got by fields) 'redirect_uri') (~(got by fields) 'code_verifier')]
      =.  pending  (~(put by pending) request [rid client (~(gut by fields) 'deviceIdentifier' 'native') (add now.bowl ~s30)])
      :_  this
      :~  [%pass /exchange/[request] %agent [our.bowl %connect] %poke %connect-exchange !>(data)]
          [%pass /exchange-timeout/[request] %arvo %b %wait (add now.bowl ~s30)]
      ==
    ?.  =(kind 'refresh_token')  (reply rid 400 invalid)
    =/  digest  (shax (~(got by fields) 'refresh_token'))
    =/  found  (skim ~(tap by sessions) |=([p=@t q=session] &(=(client client.q) |(=(digest refresh.q) (~(has in consumed.q) digest)))))
    ?~  found  (reply rid 400 invalid)
    =/  sid  p.i.found
    =/  value  q.i.found
    ?:  =(~ (grant sid))
      =.  sessions  (~(del by sessions) sid)
      =.  cache.state  (~(del by cache.state) sid)
      (reply rid 400 invalid)
    =/  cached  (~(get by cache.state) sid)
    ?:  ?&  ?=(^ cached)  (lth now.bowl until.u.cached)
            |(=(digest old.u.cached) =(digest refresh.value))
        ==
      (reply rid 200 response.u.cached)
    ?:  |((~(has in consumed.value) digest) (gte (lent ~(tap in consumed.value)) 4.096))
      =.  sessions  (~(del by sessions) sid)
      =.  cache.state  (~(del by cache.state) sid)
      =/  result  (reply rid 400 invalid)
      [[(revoke-card our.bowl sid) -.result] +.result]
    (issue rid sid 'native')
  ++  account-keys
    ^-  json
    %-  pairs:enjs:format
    :~  ['publicKeyEncryptionKeyPair' (pairs:enjs:format ~[['wrappedPrivateKey' (opt:v account 'privateKey')] ['publicKey' (opt:v account 'publicKey')] ['Object' s+'publicKeyEncryptionKeyPair']])]
        ['Object' s+'privateKeys']
    ==
  ++  profile
    ^-  json
    %-  pairs:enjs:format
    :~  ['object' s+'profile']
        ['id' s+'00000000-0000-4000-8000-000000000001']
        ['name' s+'Urbit vault']
        ['email' (opt:v account 'email')]
        ['emailVerified' b+%.y]
        ['premium' b+%.n]
        ['premiumFromOrganization' b+%.n]
        ['masterPasswordHint' ~]
        ['culture' s+'en-US']
        ['twoFactorEnabled' b+%.n]
        ['key' (opt:v account 'key')]
        ['privateKey' (opt:v account 'privateKey')]
        ['accountKeys' account-keys]
        ['securityStamp' s+'connect-sso-v1']
        ['organizations' a+~]
        ['providers' a+~]
        ['forcePasswordReset' b+%.n]
        ['usesKeyConnector' b+%.n]
    ==
  ++  unlock-data
    ^-  json
    %-  pairs:enjs:format
    :~  ['Kdf' (pairs:enjs:format ~[['KdfType' n+'0'] ['Iterations' n+'600000'] ['Memory' ~] ['Parallelism' ~]])]
        ['MasterKeyEncryptedUserKey' (opt:v account 'key')]
        ['MasterKeyWrappedUserKey' (opt:v account 'key')]
        ['Salt' (opt:v account 'email')]
    ==
  ::  The 64 KiB / 4 MiB record budget excludes the deletion timestamp.
  ::  A server-owned ISO timestamp replaces null with 22 additional bytes.
  ::  Reserve at most 22 bytes per retained item: 65,558 per record and
  ::  4,216,304 total serialized bytes at the existing 1,000-item cap.
  ::  Normalizing only deletedDate preserves every previously accepted item.
  ++  cipher-size
    |=  value=json
    ^-  @ud
    (met 3 (en:json:html (put:v value 'deletedDate' ~)))
  ++  set-deleted
    |=  [rid=@ta id=@t method=@tas deleted=?]
    ^-  (quip card _this)
    =/  old=(unit json)  (~(get by ciphers) id)
    ?~  old  (reply rid 404 ~)
    ?.  |(=(%'PUT' method) =(%'POST' method))  (reply rid 405 ~)
    ?:  =(deleted !=(~ (opt:v u.old 'deletedDate')))
      (reply rid 200 ?:(deleted ~ u.old))
    =/  next=@da  (next-time:v now.bowl revision.state)
    =/  stamp=json  s+(iso:v next)
    =/  stored=json  (put:v u.old 'deletedDate' ?:(deleted stamp ~))
    =.  stored  (put:v stored 'revisionDate' stamp)
    ::  Hard serialized bounds include the reserved lifecycle metadata.
    ?:  (gth (met 3 (en:json:html stored)) 65.558)  (reply rid 413 ~)
    =/  updated  (~(put by ciphers) id stored)
    =/  size  (roll ~(val by updated) |=([value=json total=@ud] (add total (met 3 (en:json:html value)))))
    ?:  (gth size 4.216.304)  (reply rid 413 ~)
    =.  ciphers  updated
    =.  revision.state  next
    (reply rid 200 ?:(deleted ~ stored))
  ++  save-cipher
    |=  [rid=@ta id=@t data=json old=json]
    ^-  (quip card _this)
    ?.  ?=([%o *] data)  (reply rid 400 ~)
    ?.  ?=([%s *] (opt:v data 'name'))  (reply rid 400 ~)
    ?:  !=(~ (opt:v data 'organizationId'))  (reply rid 400 ~)
    =/  known=json  (opt:v data 'lastKnownRevisionDate')
    ?:  &(!=(~ old) !=(~ known) !=(known (opt:v old 'revisionDate')))
      (reply rid 409 (pairs:enjs:format ~[['message' s+'Item changed; synchronize before editing.']]))
    =/  next=@da  (next-time:v now.bowl revision.state)
    =/  stamp=json  s+(iso:v next)
    =/  stored=json  data
    =.  stored  (put:v stored 'id' s+id)
    =.  stored  (put:v stored 'object' s+'cipherDetails')
    =.  stored  (put:v stored 'organizationId' ~)
    =.  stored  (put:v stored 'collectionIds' a+~)
    =.  stored  (put:v stored 'attachments' a+~)
    =.  stored  (put:v stored 'creationDate' ?~(old stamp (opt:v old 'creationDate')))
    =.  stored  (put:v stored 'revisionDate' stamp)
    =.  stored  (put:v stored 'deletedDate' ~)
    =.  stored  (put:v stored 'archivedDate' ~)
    =.  stored  (put:v stored 'edit' b+%.y)
    =.  stored  (put:v stored 'viewPassword' b+%.y)
    =.  stored  (put:v stored 'organizationUseTotp' b+%.n)
    =.  stored  (put:v stored 'permissions' (pairs:enjs:format ~[['delete' b+%.y] ['restore' b+%.y]]))
    ?:  (gth (cipher-size stored) 65.536)  (reply rid 413 ~)
    ?:  &(=(~ old) (gte (lent ~(tap by ciphers)) 1.000))  (reply rid 429 ~)
    =/  updated  (~(put by ciphers) id stored)
    =/  size  (roll ~(val by updated) |=([value=json total=@ud] (add total (cipher-size value))))
    ?:  (gth size 4.194.304)  (reply rid 413 ~)
    =.  ciphers  updated
    =.  revision.state  next
    (reply rid 200 stored)
  ++  handle
    |=  [rid=@ta req=inbound-request:eyre]
    ^-  (quip card _this)
    =/  url  (head (split:v '?' url.request.req))
    =/  method  method.request.req
    =/  headers  header-list.request.req
    =/  payload  ?~(body.request.req '' q.u.body.request.req)
    ?:  =(%'OPTIONS' method)  (reply rid 200 ~)
    =/  asset  (~(get by assets:assets) url)
    ?:  ?=(^ asset)
      ?.  =(method %'GET')  (reply rid 405 ~)
      (raw rid 200 mime.u.asset body.u.asset)
    ?:  |(=('/vault/bootstrap' url) =('/vault/enroll' url))
      ?.  &(authenticated.req =(src.bowl our.bowl))  (reply rid 401 ~)
      =/  cookie  (fall (get-header:http 'cookie' headers) '')
      ?>  !=(cookie '')
      =/  context  (shax cookie)
      ?:  &(=('/vault/bootstrap' url) =(method %'GET'))
        =/  csrf  (scot %uv (shas %csrf eny.bowl))
        =.  csrf.state  (malt (skim ~(tap by csrf.state) |=([p=@ux q=[token=@ux expires=@da]] (gth expires.q now.bowl))))
        ?:  (gte (lent ~(tap by csrf.state)) 8)  (reply rid 429 ~)
        =.  csrf.state  (~(put by csrf.state) context [(shax csrf) (add now.bowl ~m30)])
        (reply rid 200 (pairs:enjs:format ~[['csrf' s+csrf] ['enrolled' b+!=(account ~)]]))
      ?.  &(=('/vault/enroll' url) =(method %'POST') =(account ~))  (reply rid 409 ~)
      =/  proof  (~(get by csrf.state) context)
      ?>  ?=(^ proof)
      ?>  &((lth now.bowl expires.u.proof) =(token.u.proof (shax (fall (get-header:http 'x-vault-csrf' headers) ''))))
      =/  origin  (cat 3 'https://' (fall (get-header:http 'host' headers) ''))
      ?>  =(origin (fall (get-header:http 'origin' headers) ''))
      =/  data  (need (de:json:html payload))
      ?>  ?=([%o *] data)
      ?>  =((silt ~['email' 'key' 'privateKey' 'publicKey']) ~(key by p.data))
      =/  email  (str:v (get:v data 'email'))
      ?>  &((gth (met 3 email) 3) (lte (met 3 email) 254))
      ?>  (levy (trip email) |=(ch=@tD &((gte ch 33) (lte ch 126) !&((gte ch 'A') (lte ch 'Z')))))
      ?>  =('2.' (crip (scag 2 (trip (str:v (get:v data 'key'))))))
      ?>  =('2.' (crip (scag 2 (trip (str:v (get:v data 'privateKey'))))))
      ?>  (lte (met 3 payload) 16.384)
      =.  state  state(account data, origin origin, signing-key (shas %vault-sign eny.bowl), revision now.bowl)
      (reply rid 200 (pairs:enjs:format ~[['enrolled' b+%.y]]))
    ?:  =('/identity/connect/token' url)  (token rid req)
    ?:  |(=('/identity/accounts/prelogin' url) =('/identity/accounts/prelogin/password' url))
      (reply rid 400 (pairs:enjs:format ~[['error' s+'sso_required'] ['message' s+'Use Enterprise SSO with organization urbit-vault. Password login is disabled.']]))
    ?:  =('/identity/sso/prevalidate' url)
      ?.  =(method %'GET')  (reply rid 405 ~)
      =/  pieces  (split:v '?' url.request.req)
      ?>  ?=(^ pieces)
      =/  args  (form ?~(t.pieces '' i.t.pieces))
      ?.  =((~(gut by args) 'domainHint' '') 'urbit-vault')  (reply rid 400 invalid)
      (reply rid 200 (pairs:enjs:format ~[['token' s+'urbit-vault']]))
    ?:  =('/identity/connect/authorize' url)
      ?.  &(=(method %'GET') !=(account ~))  (reply rid 400 invalid)
      =/  pieces  (split:v '?' url.request.req)
      ?>  ?=(^ pieces)
      =/  args  (form ?~(t.pieces '' i.t.pieces))
      ?>  (levy ~(tap in ~(key by args)) |=(key=@t (~(has in (silt ~['client_id' 'redirect_uri' 'response_type' 'scope' 'state' 'code_challenge' 'code_challenge_method' 'response_mode' 'domain_hint' 'ssoToken'])) key)))
      ?>  &(=('urbit-vault' (~(got by args) 'domain_hint')) =('urbit-vault' (~(got by args) 'ssoToken')) =('query' (~(got by args) 'response_mode')) =('api offline_access' (~(got by args) 'scope')))
      =/  keys  ~['client_id' 'redirect_uri' 'response_type' 'scope' 'state' 'code_challenge' 'code_challenge_method']
      =/  query
        %-  crip
        %-  zing
        %+  join  "&"
        %+  turn  keys
        |=  key=@t
        "{(trip key)}={(en-urlt:html (trip (~(got by args) key)))}"
      (redirect rid (cat 3 '/connect/oauth/authorize?' query))
    ?:  =('/identity/connect/revocation' url)
      ?.  =(method %'POST')  (reply rid 405 ~)
      =/  fields  (form payload)
      =/  digest  (shax (~(gut by fields) 'token' ''))
      =/  removed  (skim ~(tap by sessions) |=([p=@t q=session] |(=(digest refresh.q) (~(has in consumed.q) digest))))
      =.  sessions  (malt (skim ~(tap by sessions) |=([p=@t q=session] !|(=(digest refresh.q) (~(has in consumed.q) digest)))))
      =.  cache.state  (malt (skim ~(tap by cache.state) |=([p=@t q=[old=@ux until=@da response=json]] (~(has by sessions) p))))
      =/  result  (reply rid 200 ~)
      [(weld (turn removed |=([p=@t q=session] (revoke-card our.bowl p))) -.result) +.result]
    ?:  =('/api/config' url)
      =/  base  ?:(=(origin.state '') (cat 3 'https://' (fall (get-header:http 'host' headers) '')) origin.state)
      =/  env  (pairs:enjs:format ~[['vault' s+base] ['api' s+(cat 3 base '/api')] ['identity' s+(cat 3 base '/identity')] ['notifications' s+(cat 3 base '/notifications')] ['sso' s+(cat 3 base '/identity')] ['cloudRegion' ~]])
      (reply rid 200 (pairs:enjs:format ~[['object' s+'config'] ['version' s+'2026.6.0'] ['server' (pairs:enjs:format ~[['name' s+'Urbit-native Bitwarden backend']])] ['environment' env] ['featureStates' o+~] ['settings' (pairs:enjs:format ~[['disableUserRegistration' b+%.y]])]]))
    ?:  =('/api/devices/knowndevice' url)  (reply rid 200 b+%.n)
    ?:  =('/api/organizations/domain/sso/details' url)
      (reply rid 200 (pairs:enjs:format ~[['object' s+'list'] ['data' a+~] ['continuationToken' ~]]))
    =/  auth  (fall (get-header:http 'authorization' headers) '')
    ?.  =("Bearer " (scag 7 (trip auth)))  (reply rid 401 ~)
    =/  digest  (shax (crip (slag 7 (trip auth))))
    =/  found  (skim ~(tap by sessions) |=([p=@t q=session] &(=(digest access.q) (lth now.bowl expires.q))))
    ?~  found  (reply rid 401 ~)
    ?:  =(~ (grant p.i.found))  (reply rid 401 ~)
    ?:  =('/api/accounts/key-management/user-key-id' url)
      ?.  =(%'POST' method.request.req)  (reply rid 405 ~)
      =/  data=json  (need (de:json:html ?~(body.request.req '{}' q.u.body.request.req)))
      =.  account  (put:v account 'userKeyId' (get:v data 'userKeyId'))
      (reply rid 200 ~)
    ?:  =('/api/accounts/profile' url)  (reply rid 200 profile)
    ?:  =('/api/accounts/revision-date' url)  (reply rid 200 (time:enjs:format revision.state))
    ?:  =('/api/sync' url)
      %^  reply  rid  200
      %-  pairs:enjs:format
      :~  ['object' s+'sync']
          ['profile' profile]
          ['userDecryption' (pairs:enjs:format ~[['userKeyId' (opt:v account 'userKeyId')] ['masterPasswordUnlock' (pairs:enjs:format ~[['kdf' (pairs:enjs:format ~[['kdfType' n+'0'] ['iterations' n+'600000'] ['memory' ~] ['parallelism' ~]])] ['masterKeyWrappedUserKey' (opt:v account 'key')] ['masterKeyEncryptedUserKey' (opt:v account 'key')] ['salt' (opt:v account 'email')]])]])]
          ['ciphers' a+~(val by ciphers)]
          ['folders' a+~(val by folders)]
          ['collections' a+~]
          ['policies' a+~]
          ['sends' a+~]
          ['domains' (pairs:enjs:format ~[['equivalentDomains' a+~] ['globalEquivalentDomains' a+~]])]
      ==
    =/  path=path  (stab url)
    =/  method=@tas  method.request.req
    =/  data=json
      ?~  body.request.req  ~
      (fall (de:json:html q.u.body.request.req) ~)
    ?+  path  (reply rid 404 ~)
        [%api %ciphers ~]
      ?:  =(%'GET' method)
        (reply rid 200 (pairs:enjs:format ~[['object' s+'list'] ['data' a+~(val by ciphers)] ['continuationToken' ~]]))
      ?.  =(%'POST' method)  (reply rid 405 ~)
      =.  serial.state  +(serial.state)
      (save-cipher rid (uuid:v +(serial.state)) data ~)
        [%api %ciphers %create ~]
      ?.  =(%'POST' method)  (reply rid 405 ~)
      =.  serial.state  +(serial.state)
      (save-cipher rid (uuid:v +(serial.state)) (get:v data 'cipher') ~)
        [%api %ciphers id=@ta ~]
      =/  old=(unit json)  (~(get by ciphers) i.t.t.path)
      ?~  old  (reply rid 404 ~)
      ?:  =(%'GET' method)  (reply rid 200 u.old)
      ?:  |(=(%'PUT' method) =(%'POST' method))
        (save-cipher rid i.t.t.path data u.old)
      ?.  =(%'DELETE' method)  (reply rid 405 ~)
      =.  ciphers  (~(del by ciphers) i.t.t.path)
      =.  revision.state  (next-time:v now.bowl revision.state)
      (reply rid 200 ~)
        [%api %ciphers id=@ta %delete ~]
      (set-deleted rid i.t.t.path method %.y)
        [%api %ciphers id=@ta %restore ~]
      (set-deleted rid i.t.t.path method %.n)
    ==
  --
++  on-watch
  |=  =path
  ^-  (quip card _this)
  ?>  (http-watch:ce sup.bowl src.bowl path)
  `this
++  on-leave  on-leave:def
++  on-peek  on-peek:def
++  on-agent
  |=  [=wire =sign:agent:gall]
  ^-  (quip card _this)
  ?:  =(wire /revoke)  `this
  ?:  ?=([%exchange @ ~] wire)
    ?:  ?=([%poke-ack ^] sign)
      =/  found  (~(get by pending) i.t.wire)
      ?~  found  `this
      =.  pending  (~(del by pending) i.t.wire)
      [(give-simple-payload:app:server rid.u.found [[400 ~[['content-type' 'application/json'] ['cache-control' 'no-store']]] `(as-octs:mimes:html '{"error":"invalid_grant"}')]) this]
    `this
  (on-agent:def wire sign)
++  on-arvo
  |=  [=wire =sign-arvo]
  ?:  ?=([%cache-expiry @ @ ~] wire)
    ?>  ?=([%behn %wake *] sign-arvo)
    =/  sid  i.t.wire
    =/  found  (~(get by cache.state) sid)
    ?~  found  `this
    ::  A delayed wake for an older response must not remove its replacement.
    ?.  =(i.t.t.wire (scot %da until.u.found))  `this
    ?:  (lth now.bowl until.u.found)
      [~[(cache-wait sid until.u.found)] this]
    `this(cache.state (~(del by cache.state) sid))
  ?:  ?=([%exchange-timeout @ ~] wire)
    ?>  ?=([%behn %wake *] sign-arvo)
    =/  found  (~(get by pending) i.t.wire)
    ?~  found  `this
    [(unavailable rid.u.found) this(pending (~(del by pending) i.t.wire))]
  ?:  ?=([%bind *] wire)
    ?>  ?=([%eyre %bound *] sign-arvo)
    ?>  accepted.sign-arvo
    `this
  (on-arvo:def wire sign-arvo)
++  on-fail  on-fail:def
--
