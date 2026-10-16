::  Urbit-native Bitwarden backend. Connect remains the authorization authority.
/-  c=connect
/+  default-agent, server, v=vault-json, ce=connect-entry, assets=vault-assets
|%
+$  card  card:agent:gall
+$  session  [client=@t expires=@da access=@ux refresh=@ux consumed=(set @ux)]
+$  vault-data
  $:  account=json  signing-key=@  origin=@t
      sessions=(map @t session)  ciphers=(map @t json)  folders=(map @t json)
      serial=@ud  revision=@da
      cache=(map @t [old=@ux until=@da response=json])
      csrf=(map @ux [token=@ux expires=@da])
  ==
+$  vault-state  [%1 vault-data]
++  revoke-card
  |=  [ship=@p sid=@t]
  ^-  card
  [%pass /revoke %agent [ship %connect] %poke %connect-revoke !>(`revoke-request:c`[%bitwarden sid])]
++  cache-wait
  |=  [sid=@t until=@da]
  ^-  card
  [%pass /cache-expiry/[sid]/[(scot %da until)] %arvo %b %wait until]
++  service-origin
  |=  value=@t
  ^-  @t
  ?:  =(value '')  ''
  ?:  ?&  (gte (met 3 value) 15)
          =('/apps/bitwarden' (crip (slag (sub (met 3 value) 15) (trip value))))
      ==
    value
  (cat 3 value '/apps/bitwarden')
++  route-cards
  ^-  (list card)
  ::  Eyre only disconnects a binding owned by the same original duct.
  :~  [%pass /bind/root %arvo %e %disconnect `/]
      [%pass /bind/api %arvo %e %disconnect `/api]
      [%pass /bind/identity %arvo %e %disconnect `/identity]
      [%pass /bind/vault %arvo %e %connect `/apps/bitwarden %bitwarden]
  ==
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
  [route-cards this]
++  on-save  !>(state)
++  on-load
  |=  old=vase
  ^-  (quip card _this)
  =/  legacy  ?=(%0 -.q.old)
  =.  state
    ?:  legacy
      =/  previous  !<([%0 vault-data] old)
      [%1 +.previous]
    !<(vault-state old)
  ::  Old JWT ids disclosed refresh entropy. Reauthorize once on upgrade.
  =/  revoked=(list card)
    ?.  legacy  ~
    (turn ~(tap by sessions) |=([p=@t q=session] (revoke-card our.bowl p)))
  =?  state  legacy  state(sessions ~, cache ~, csrf ~)
  =.  pending  ~
  =.  origin.state  (service-origin origin.state)
  =?  account  &(!=(account ~) =((opt:v account 'creationDate') ~))
    (put:v account 'creationDate' s+(iso:v revision.state))
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
  [(weld revoked (weld route-cards (weld timers completed))) this]
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
  ::  Official clients import the encrypted personal vault in one request.
  =/  request-path  (head (split:v '?' url.request.req))
  =/  body-limit  ?:(=(request-path '/apps/bitwarden/api/ciphers/import') 6.291.456 262.144)
  ?:  &(?=(^ body.request.req) (gth p.u.body.request.req body-limit))  (reply rid 413 ~)
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
    ::  The official CLI refreshes below five minutes while persisting tokens.
    ::  Only its first issuance needs headroom; rotated tokens retain 60 seconds.
    =/  lifetime=@ud  ?:(&(=('cli' client.value) =(0 refresh.value)) 360 60)
    =/  expiry  (add now.bowl (mul ~s1 lifetime))
    =/  claims
      %-  pairs:enjs:format
      :~  ['sub' s+'00000000-0000-4000-8000-000000000001']
          ['email' (opt:v account 'email')]  ['email_verified' b+%.y]
          ['name' s+'Urbit vault']  ['premium' b+%.n]
          ['iss' s+(cat 3 origin.state '/identity')]  ['aud' s+'api']
          ['exp' (sect:enjs:format expiry)]  ['nbf' (sect:enjs:format now.bowl)]
          ['iat' (sect:enjs:format now.bowl)]  ['amr' a+~[s+'Application']]
          ['scope' a+~[s+'api' s+'offline_access']]  ['device' s+device]
          ['sstamp' s+'connect-sso-v1']  ['jti' s+(token-id:v eny.bowl)]
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
          ['expires_in' (numb:enjs:format lifetime)]  ['token_type' s+'Bearer']
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
    ?.  (~(has in (silt ~['cli' 'browser' 'desktop' 'mobile'])) client)  (reply rid 400 invalid)
    =/  allowed
      ?:  =(kind 'authorization_code')  (silt ~['scope' 'grant_type' 'client_id' 'code' 'code_verifier' 'redirect_uri' 'deviceType' 'deviceIdentifier' 'deviceName' 'devicePushToken' 'twoFactorRemember' 'deeplinkScheme' 'username'])
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
        ['creationDate' (opt:v account 'creationDate')]
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
  ++  cipher-record
    |=  [id=@t data=json old=json stamp=json]
    ^-  json
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
    stored
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
    =/  stored=json  (cipher-record id data old stamp)
    ?:  (gth (cipher-size stored) 65.536)  (reply rid 413 ~)
    ?:  &(=(~ old) (gte (lent ~(tap by ciphers)) 1.000))  (reply rid 429 ~)
    =/  updated  (~(put by ciphers) id stored)
    =/  size  (roll ~(val by updated) |=([value=json total=@ud] (add total (cipher-size value))))
    ?:  (gth size 4.194.304)  (reply rid 413 ~)
    =.  ciphers  updated
    =.  revision.state  next
    (reply rid 200 stored)
  ++  fresh-id
    |=  [number=@ud vault=(map @t json) dirs=(map @t json)]
    ^-  [id=@t serial=@ud]
    =/  serial  +(number)
    ::  Preserve the existing sequence and skip identifiers from older state.
    =/  id  (uuid:v +(serial))
    ?:  |((~(has by vault) id) (~(has by dirs) id))
      $(number serial)
    [id serial]
  ++  folder-record
    |=  [id=@t name=json stamp=json]
    ^-  json
    (pairs:enjs:format ~[['object' s+'folder'] ['id' s+id] ['name' name] ['revisionDate' stamp]])
  ++  folder-bytes
    |=  values=(map @t json)
    ^-  @ud
    (roll ~(val by values) |=([value=json total=@ud] (add total (met 3 (en:json:html value)))))
  ++  save-folder
    |=  [rid=@ta id=@t data=json]
    ^-  (quip card _this)
    =/  name  (opt:v data 'name')
    ?.  ?=([%s *] name)  (reply rid 400 ~)
    =/  next=@da  (next-time:v now.bowl revision.state)
    =/  stored  (folder-record id name s+(iso:v next))
    ?:  (gth (met 3 (en:json:html stored)) 65.536)  (reply rid 413 ~)
    =/  updated  (~(put by folders) id stored)
    ?:  (gth (lent ~(tap by updated)) 1.000)  (reply rid 429 ~)
    ?:  (gth (folder-bytes updated) 1.048.576)  (reply rid 413 ~)
    =.  folders  updated
    =.  revision.state  next
    (reply rid 200 stored)
  ++  remove-folders
    |=  [rid=@ta ids=(set @t)]
    ^-  (quip card _this)
    =/  next=@da  (next-time:v now.bowl revision.state)
    =.  folders  (malt (skim ~(tap by folders) |=([p=@t q=json] !(~(has in ids) p))))
    =.  ciphers
      %-  malt
      %+  turn  ~(tap by ciphers)
      |=  [p=@t q=json]
      ^-  [@t json]
      ?.  (~(has in ids) (str:v (opt:v q 'folderId')))  [p q]
      [p (put:v (put:v q 'folderId' ~) 'revisionDate' s+(iso:v next))]
    =.  revision.state  next
    (reply rid 200 ~)
  ++  bulk-remove-folders
    |=  [rid=@ta data=json]
    ^-  (quip card _this)
    =/  ids  (opt:v data 'ids')
    ?.  ?=([%a *] ids)  (reply rid 400 ~)
    ?.  (levy p.ids |=(item=json ?=([%s *] item)))  (reply rid 400 ~)
    (remove-folders rid (silt (turn p.ids str:v)))
  ++  import-vault
    |=  [rid=@ta data=json]
    ^-  (quip card _this)
    ?.  ?=([%o *] data)  (reply rid 400 ~)
    =/  incoming  (opt:v data 'ciphers')
    =/  directories  (opt:v data 'folders')
    =/  links  (opt:v data 'folderRelationships')
    ?.  ?=([%a *] incoming)  (reply rid 400 ~)
    =?  directories  =(directories ~)  a+~
    =?  links  =(links ~)  a+~
    ?.  &(?=([%a *] directories) ?=([%a *] links))  (reply rid 400 ~)
    ?:  (gth (add (lent p.incoming) (lent ~(tap by ciphers))) 1.000)  (reply rid 429 ~)
    ?:  (gth (lent p.directories) 1.000)  (reply rid 429 ~)
    =/  next=@da  (next-time:v now.bowl revision.state)
    =/  stamp=json  s+(iso:v next)
    ::  All changes stay in local candidates until the whole import succeeds.
    =/  dirs=(map @t json)  folders
    =/  vault=(map @t json)  ciphers
    =/  number=@ud  serial.state
    =/  indices=(map @ud @t)  ~
    =/  directory-list=(list json)  p.directories
    =/  directory-index=@ud  0
    =/  prepared=[status=@ud dirs=(map @t json) number=@ud indices=(map @ud @t)]
      |-
      ?~  directory-list  [200 dirs number indices]
      =/  item=json  i.directory-list
      =/  name=json  (opt:v item 'name')
      ?.  ?=([%s *] name)  [400 dirs number indices]
      =/  hint=@t  (str:v (opt:v item 'id'))
      ::  File hints may only reuse folders present before this request.
      ?:  &(!=(hint '') (~(has by folders) hint))
        $(directory-list t.directory-list, directory-index +(directory-index), indices (~(put by indices) directory-index hint))
      =^  id=@t  number  (fresh-id number vault dirs)
      =/  stored=json  (folder-record id name stamp)
      ?:  (gth (met 3 (en:json:html stored)) 65.536)  [413 dirs number indices]
      =.  dirs  (~(put by dirs) id stored)
      ?:  (gth (lent ~(tap by dirs)) 1.000)  [429 dirs number indices]
      ?:  (gth (folder-bytes dirs) 1.048.576)  [413 dirs number indices]
      $(directory-list t.directory-list, directory-index +(directory-index), indices (~(put by indices) directory-index id))
    ?.  =(200 status.prepared)  (reply rid status.prepared ~)
    =.  dirs  dirs.prepared
    =.  number  number.prepared
    =.  indices  indices.prepared
    =/  relations=(map @ud @t)  ~
    =/  link-list=(list json)  p.links
    =/  mapped=(unit (map @ud @t))
      |-
      ?~  link-list  `relations
      =/  key=json  (opt:v i.link-list 'key')
      =/  value=json  (opt:v i.link-list 'value')
      ?.  &(?=([%n *] key) ?=([%n *] value))  ~
      =/  cipher-index=(unit @ud)  (rush p.key dem)
      =/  folder-index=(unit @ud)  (rush p.value dem)
      ?~  cipher-index  ~
      ?~  folder-index  ~
      ?.  (lth u.cipher-index (lent p.incoming))  ~
      =/  dir=(unit @t)  (~(get by indices) u.folder-index)
      ?~  dir  ~
      ?:  (~(has by relations) u.cipher-index)  ~
      $(link-list t.link-list, relations (~(put by relations) u.cipher-index u.dir))
    ?~  mapped  (reply rid 400 ~)
    =.  relations  u.mapped
    =/  cipher-list=(list json)  p.incoming
    =/  cipher-index=@ud  0
    =/  bytes=@ud  (roll ~(val by vault) |=([value=json total=@ud] (add total (cipher-size value))))
    =/  imported=[status=@ud vault=(map @t json) number=@ud]
      |-
      ?~  cipher-list  [200 vault number]
      =/  item=json  i.cipher-list
      ?.  ?=([%o *] item)  [400 vault number]
      ?.  ?=([%s *] (opt:v item 'name'))  [400 vault number]
      ?:  !=(~ (opt:v item 'organizationId'))  [400 vault number]
      =/  dir=(unit @t)  (~(get by relations) cipher-index)
      =/  linked=json  ?~(dir item (put:v item 'folderId' s+u.dir))
      =/  folder=json  (opt:v linked 'folderId')
      ?:  &(!=(~ folder) !(~(has by dirs) (str:v folder)))  [400 vault number]
      =^  id=@t  number  (fresh-id number vault dirs)
      =/  stored=json  (cipher-record id linked ~ stamp)
      =/  size=@ud  (cipher-size stored)
      ?:  (gth size 65.536)  [413 vault number]
      =.  bytes  (add bytes size)
      ?:  (gth bytes 4.194.304)  [413 vault number]
      $(cipher-list t.cipher-list, cipher-index +(cipher-index), vault (~(put by vault) id stored))
    ?.  =(200 status.imported)  (reply rid status.imported ~)
    =.  folders  dirs
    =.  ciphers  vault.imported
    =.  serial.state  number.imported
    =.  revision.state  next
    (reply rid 200 ~)
  ++  handle
    |=  [rid=@ta req=inbound-request:eyre]
    ^-  (quip card _this)
    =/  original  (head (split:v '?' url.request.req))
    ?.  |(=(original '/apps/bitwarden') =('/apps/bitwarden/' (crip (scag 16 (trip original)))))
      (reply rid 404 ~)
    =/  local-url  (crip (slag 15 (trip url.request.req)))
    =.  req  req(url.request ?:(=(local-url '') '/' local-url))
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
        (reply rid 200 (pairs:enjs:format ~[['csrf' s+csrf] ['enrolled' b+!=(account ~)] ['email' (opt:v account 'email')] ['webVaultURL' s+(service-origin (cat 3 'https://' (fall (get-header:http 'host' headers) '')))]]))
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
      =.  state  state(account (put:v data 'creationDate' s+(iso:v now.bowl)), origin (service-origin origin), signing-key (shas %vault-sign eny.bowl), revision now.bowl)
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
      =/  base  (service-origin ?:(=(origin.state '') (cat 3 'https://' (fall (get-header:http 'host' headers) '')) origin.state))
      =/  env  (pairs:enjs:format ~[['vault' s+base] ['api' s+(cat 3 base '/api')] ['identity' s+(cat 3 base '/identity')] ['notifications' s+(cat 3 base '/notifications')] ['sso' s+(cat 3 base '/identity')] ['cloudRegion' ~]])
      (reply rid 200 (pairs:enjs:format ~[['object' s+'config'] ['version' s+'2026.6.0'] ['server' (pairs:enjs:format ~[['name' s+'Urbit-native Bitwarden backend'] ['url' s+base]])] ['environment' env] ['featureStates' o+~] ['settings' (pairs:enjs:format ~[['disableUserRegistration' b+%.y]])]]))
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
        [%api %folders ~]
      ?:  =(%'GET' method)
        (reply rid 200 (pairs:enjs:format ~[['object' s+'list'] ['data' a+~(val by folders)] ['continuationToken' ~]]))
      ?:  =(%'DELETE' method)  (bulk-remove-folders rid data)
      ?.  =(%'POST' method)  (reply rid 405 ~)
      =^  id=@t  serial.state  (fresh-id serial.state ciphers folders)
      (save-folder rid id data)
        [%api %folders %all ~]
      ?.  =(%'DELETE' method)  (reply rid 405 ~)
      (remove-folders rid ~(key by folders))
        [%api %folders id=@ta ~]
      ?.  (~(has by folders) i.t.t.path)  (reply rid 404 ~)
      ?:  =(%'GET' method)  (reply rid 200 (~(got by folders) i.t.t.path))
      ?:  =(%'PUT' method)  (save-folder rid i.t.t.path data)
      ?.  =(%'DELETE' method)  (reply rid 405 ~)
      (remove-folders rid (silt ~[i.t.t.path]))
        [%api %ciphers %import ~]
      ?.  =(%'POST' method)  (reply rid 405 ~)
      (import-vault rid data)
        [%api %ciphers ~]
      ?:  =(%'GET' method)
        (reply rid 200 (pairs:enjs:format ~[['object' s+'list'] ['data' a+~(val by ciphers)] ['continuationToken' ~]]))
      ?.  =(%'POST' method)  (reply rid 405 ~)
      =^  id=@t  serial.state  (fresh-id serial.state ciphers folders)
      (save-cipher rid id data ~)
        [%api %ciphers %create ~]
      ?.  =(%'POST' method)  (reply rid 405 ~)
      =^  id=@t  serial.state  (fresh-id serial.state ciphers folders)
      (save-cipher rid id (get:v data 'cipher') ~)
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
