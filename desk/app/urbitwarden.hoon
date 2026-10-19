::  Urbitwarden backend. Connect remains the authorization authority.
/-  c=connect
/+  default-agent, server, v=vault-json, ce=connect-entry, assets=vault-assets, va=vault-attachments, vd=vault-domains, vk=vault-keys
|%
+$  card  card:agent:gall
+$  session  [client=@t expires=@da access=@ux refresh=@ux consumed=(set @ux)]
+$  vault-data-v1
  $:  account=json  signing-key=@  origin=@t
      sessions=(map @t session)  ciphers=(map @t json)  folders=(map @t json)
      serial=@ud  revision=@da
      cache=(map @t [old=@ux until=@da response=json])
      csrf=(map @ux [token=@ux expires=@da])
  ==
+$  vault-data
  $:  account=json  signing-key=@  origin=@t
      sessions=(map @t session)  ciphers=(map @t json)  folders=(map @t json)
      serial=@ud  revision=@da
      cache=(map @t [old=@ux until=@da response=json])
      csrf=(map @ux [token=@ux expires=@da])
      attachments=store:va  trash-next=(unit @da)
  ==
+$  vault-state  [%2 vault-data]
++  connect-client
  |=  client=@t
  ^-  @t
  ?>  (~(has in (silt ~['cli' 'browser' 'desktop' 'mobile'])) client)
  (cat 3 'urbitwarden-' client)
++  revoke-card
  |=  [ship=@p sid=@t]
  ^-  card
  [%pass /revoke %agent [ship %connect] %poke %connect-revoke !>(`revoke-request:c`[%urbitwarden sid])]
++  cache-wait
  |=  [sid=@t until=@da]
  ^-  card
  [%pass /cache-expiry/[sid]/[(scot %da until)] %arvo %b %wait until]
++  service-origin
  |=  value=@t
  ^-  @t
  ?:  =(value '')  ''
  =/  current  '/apps/urbitwarden'
  ?:  &((gte (met 3 value) (met 3 current)) =(current (crip (slag (sub (met 3 value) (met 3 current)) (trip value)))))
    value
  (cat 3 value current)
++  route-cards
  ^-  (list card)
  ::  Eyre only disconnects a binding owned by the same original duct.
  :~  [%pass /bind/root %arvo %e %disconnect `/]
      [%pass /bind/api %arvo %e %disconnect `/api]
      [%pass /bind/identity %arvo %e %disconnect `/identity]
      [%pass /bind/vault %arvo %e %connect `/apps/urbitwarden %urbitwarden]
      ::  Remove the route owned by the previous compatibility release.
      [%pass /bind/legacy %arvo %e %disconnect `/apps/bitwarden]
  ==
++  unavailable
  |=  rid=@ta
  ^-  (list card)
  (give-simple-payload:app:server rid [[503 ~[['content-type' 'application/json'] ['cache-control' 'no-store']]] `(as-octs:mimes:html '{"error":"temporarily_unavailable"}')])
--
^-  agent:gall
=|  state=vault-state
=|  pending=(map @t [rid=@ta client=@t device=@t until=@da])
=|  downloads=(map @t [sid=@t cipher=@t attachment=@t until=@da])
=*  account  account.state
=*  sessions  sessions.state
=*  ciphers  ciphers.state
=*  folders  folders.state
|_  =bowl:gall
+*  this  .
    def  ~(. (default-agent this %|) bowl)
    trash-retention
      ^-  (unit @ud)
      =/  value  (opt:v account 'trashAutoDeleteDays')
      ?.  ?=([%n *] value)  ~
      =/  days  (rush p.value dem)
      ?~  days  ~
      ?:  =(0 u.days)  ~
      days
    trash-cards
      ^-  (list card)
      ?~  trash-retention  ~
      ?~  trash-next.state  ~
      ~[[%pass /trash-cleanup/[(scot %da u.trash-next.state)] %arvo %b %wait u.trash-next.state]]
    expire-trash
      ^-  _this
      =/  retention  trash-retention
      ?~  retention  this
      =/  duration  (mul u.retention ~d1)
      ?:  (gth duration now.bowl)  this
      =/  cutoff  (sub now.bowl duration)
      =/  expired=(set @t)
        =/  rows
          %+  skim  ~(tap by ciphers)
          |=  [p=@t q=json]
          =/  stamp  (opt:v q 'deletedDate')
          ?.  ?=([%s *] stamp)  |
          =/  parsed  (stud:chrono:userlib p.stamp)
          ?~  parsed  |
          (lte (year u.parsed) cutoff)
        (silt (turn rows |=([p=@t q=json] p)))
      ?:  =(~ expired)  this
      =.  ciphers  (malt (skim ~(tap by ciphers) |=([p=@t q=json] !(~(has in expired) p))))
      =.  attachments.state  (malt (skim ~(tap by attachments.state) |=([p=@t q=attachment:va] !(~(has in expired) cipher.q))))
      =.  downloads  (malt (skim ~(tap by downloads) |=([p=@t q=[sid=@t cipher=@t attachment=@t until=@da]] !(~(has in expired) cipher.q))))
      this(revision.state (next-time:v now.bowl revision.state))
++  on-init
  ^-  (quip card _this)
  [route-cards this]
++  on-save  !>(state)
++  on-load
  |=  old=vase
  ^-  (quip card _this)
  =/  legacy  ?=(%0 -.q.old)
  =.  state
    ?:  ?=(%2 -.q.old)  !<(vault-state old)
    ?>  |(?=(%0 -.q.old) ?=(%1 -.q.old))
    =/  previous  !<([version=@ud vault-data-v1] old)
    :*  %2  account.previous  signing-key.previous  origin.previous
        sessions.previous  ciphers.previous  folders.previous
        serial.previous  revision.previous  cache.previous  csrf.previous  ~  ~
    ==
  ::  Old JWT ids disclosed refresh entropy. Reauthorize once on upgrade.
  =/  revoked=(list card)
    ?.  legacy  ~
    (turn ~(tap by sessions) |=([p=@t q=session] (revoke-card our.bowl p)))
  =?  state  legacy  state(sessions ~, cache ~, csrf ~)
  =.  pending  ~
  =.  downloads  ~
  =?  trash-next.state  &(?=(^ trash-retention) ?=(~ trash-next.state))  `(add now.bowl ~d1)
  =?  trash-next.state  ?=(~ trash-retention)  ~
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
  [(weld trash-cards (weld revoked (weld route-cards (weld timers completed)))) this]
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
  =/  attempt  (mule |.(!>((handle rid req))))
  ?:  ?=(%| -.attempt)  (reply rid 400 invalid)
  !<((quip card _this) p.attempt)
  ++  grant
    |=  sid=@t
    ^-  json
    =/  value  .^(json %gx /(scot %p our.bowl)/connect/(scot %da now.bowl)/integration/urbitwarden/[sid]/json)
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
  ++  website-icon
    |=  [rid=@ta domain=@t method=@tas]
    ^-  (quip card _this)
    ?.  =(%'GET' method)  (reply rid 405 ~)
    ::  Icons are public website data. Redirect the client to the website itself;
    ::  the ship is never an unauthenticated network proxy or credential sender.
    =/  labels  (split:v '.' domain)
    =/  valid-label
      |=  label=@t
      ^-  ?
      =/  chars  (trip label)
      ?~  chars  |
      ?.  (lte (lent chars) 63)  |
      ?:  |(=(i.chars '-') =((rear chars) '-'))  |
      (levy ^-(tape chars) |=(ch=@tD |(&((gte ch 'a') (lte ch 'z')) &((gte ch 'A') (lte ch 'Z')) &((gte ch '0') (lte ch '9')) =(ch '-'))))
    ?.  &((lte (met 3 domain) 253) (levy labels valid-label))  (reply rid 404 ~)
    (redirect rid (rap 3 ~['https://' domain '/favicon.ico']))
  ++  attachment-list
    |=  id=@t
    ^-  json
    :-  %a
    %+  turn  (entries:va attachments.state id)
    |=  [p=@t q=attachment:va]
    (metadata:va p q origin.state ~)
  ++  update-attachments
    |=  id=@t
    ^-  _this
    =/  next  (next-time:v now.bowl revision.state)
    =/  old  (~(got by ciphers) id)
    =.  old  (put:v old 'attachments' (attachment-list id))
    =.  old  (put:v old 'revisionDate' s+(iso:v next))
    this(ciphers (~(put by ciphers) id old), revision.state next)
  ++  prepare-attachment
    |=  [rid=@ta id=@t data=json]
    ^-  (quip card _this)
    =/  old  (~(get by ciphers) id)
    ?~  old  (reply rid 404 ~)
    ?:  =((opt:v data 'adminRequest') b+%.y)  (reply rid 400 ~)
    =/  name  (text-field:va data 'fileName')
    =/  key  (text-field:va data 'key')
    =/  size  (opt:v data 'fileSize')
    ?~  name  (reply rid 400 ~)
    ?~  key  (reply rid 400 ~)
    =/  bytes=(unit @ud)
      ?+  size  ~
        [%n *]  (rush p.size dem)
        [%s *]  (rush p.size dem)
      ==
    ?~  bytes  (reply rid 400 ~)
    =/  known  (opt:v data 'lastKnownRevisionDate')
    ?:  &(!=(~ known) !=(known (opt:v u.old 'revisionDate')))  (reply rid 409 ~)
    =^  aid=@t  serial.state  (fresh-id serial.state ciphers folders)
    =.  attachments.state  (~(put by attachments.state) aid [id u.name u.key u.bytes ~])
    =.  this  (update-attachments id)
    %^  reply  rid  200
    %-  pairs:enjs:format
    :~  ['object' s+'attachment-fileUpload']
        ['attachmentId' s+aid]
        ['fileUploadType' n+'0']
        ['url' s+(rap 3 ~['/ciphers/' id '/attachment/' aid])]
        ['cipherResponse' (~(got by ciphers) id)]
    ==
  ++  attachment-request
    |=  [rid=@ta id=@t aid=@t sid=@t req=inbound-request:eyre]
    ^-  (quip card _this)
    =/  value  (~(get by attachments.state) aid)
    ?~  value  (reply rid 404 ~)
    ?.  &(=(cipher.u.value id) (~(has by ciphers) id))  (reply rid 404 ~)
    =/  method  method.request.req
    ?:  =(%'DELETE' method)  (delete-attachment rid id aid)
    ?:  =(%'POST' method)
      ?~  body.request.req  (reply rid 400 ~)
      =/  content  (extract:va header-list.request.req u.body.request.req)
      ?~  content  (reply rid 400 ~)
      =/  completed  (complete:va u.value u.content)
      ?~  completed  (reply rid 400 ~)
      =.  attachments.state  (~(put by attachments.state) aid u.completed)
      ::  Clients retain the prepare response's item revision after upload.
      ::  Finalizing the bytes changes sync state, not the item metadata.
      =?  revision.state  ?=(~ content.u.value)
        (next-time:v now.bowl revision.state)
      (reply rid 200 ~)
    ?.  =(%'GET' method)  (reply rid 405 ~)
    ?~  content.u.value  (reply rid 404 ~)
    =/  token  (scot %uv (shas %attachment-download eny.bowl))
    =/  key  (scot %uv (shax token))
    =.  downloads  (malt (skim ~(tap by downloads) |=([p=@t q=[sid=@t cipher=@t attachment=@t until=@da]] (lth now.bowl until.q))))
    =.  downloads  (~(put by downloads) key [sid id aid (add now.bowl ~m1)])
    =/  url  (rap 3 ~[origin.state '/attachments/' id '/' aid '?token=' token])
    (reply rid 200 (metadata:va aid u.value origin.state `url))
  ++  delete-attachment
    |=  [rid=@ta id=@t aid=@t]
    ^-  (quip card _this)
    =/  value  (~(get by attachments.state) aid)
    ?~  value  (reply rid 404 ~)
    ?.  &(=(cipher.u.value id) (~(has by ciphers) id))  (reply rid 404 ~)
    =.  attachments.state  (~(del by attachments.state) aid)
    =.  downloads  (malt (skim ~(tap by downloads) |=([p=@t q=[sid=@t cipher=@t attachment=@t until=@da]] !=(attachment.q aid))))
    =.  this  (update-attachments id)
    (reply rid 200 (pairs:enjs:format ~[['cipher' (~(got by ciphers) id)]]))
  ++  download-attachment
    |=  [rid=@ta id=@t aid=@t req=inbound-request:eyre]
    ^-  (quip card _this)
    ?.  =(%'GET' method.request.req)  (reply rid 405 ~)
    =/  parts  (split:v '?' url.request.req)
    =/  args  (form ?~(parts '' ?~(t.parts '' i.t.parts)))
    =/  key  (scot %uv (shax (~(gut by args) 'token' '')))
    =/  ticket  (~(get by downloads) key)
    ?~  ticket  (reply rid 401 ~)
    ?.  &((lth now.bowl until.u.ticket) =(cipher.u.ticket id) =(attachment.u.ticket aid) (~(has by sessions) sid.u.ticket))  (reply rid 401 ~)
    ?:  =(~ (grant sid.u.ticket))  (reply rid 401 ~)
    =/  value  (~(get by attachments.state) aid)
    ?~  value  (reply rid 404 ~)
    ?.  &(=(cipher.u.value id) (~(has by ciphers) id))  (reply rid 404 ~)
    ?~  content.u.value  (reply rid 404 ~)
    :_  this
    (give-simple-payload:app:server rid [[200 ~[['content-type' 'application/octet-stream'] ['cache-control' 'no-store'] ['x-content-type-options' 'nosniff'] ['referrer-policy' 'no-referrer']]] content.u.value])
  ++  redirect
    |=  [rid=@ta to=@t]
    ^-  (quip card _this)
    :_  this
    (give-simple-payload:app:server rid [[302 ~[['location' to] ['cache-control' 'no-store'] ['referrer-policy' 'no-referrer']]] ~])
  ++  login-redirect
    |=  rid=@ta
    ^-  (quip card _this)
    ::  Browser-only SSO fragments must survive the native login form.
    ::  This fixed script is the only content allowed by the CSP hash below.
    =/  script  (crip "location.replace('/~/login?redirect='+encodeURIComponent(location.pathname+location.search+location.hash));")
    =/  txt  (cat 3 '<!doctype html><meta charset="utf-8"><script>' (cat 3 script '</script><noscript><meta http-equiv="refresh" content="0;url=/~/login"></noscript>'))
    :_  this
    %+  give-simple-payload:app:server  rid
    :-  [200 ~[['content-type' 'text/html; charset=utf-8'] ['cache-control' 'no-store'] ['x-content-type-options' 'nosniff'] ['referrer-policy' 'no-referrer'] ['x-frame-options' 'DENY'] ['content-security-policy' (crip "default-src 'none'; script-src 'sha256-ukhDgfIs0bp4r5mcgYSBAGLCBP2vmInfdryuQIx3zxA='; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")]]]
    `[p=(met 3 txt) q=txt]
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
          ['name' ?:(=(~ (opt:v account 'name')) s+'Urbit vault' (opt:v account 'name'))]  ['premium' b+%.y]
          ['iss' s+(cat 3 origin.state '/identity')]  ['aud' s+'api']
          ['exp' (sect:enjs:format expiry)]  ['nbf' (sect:enjs:format now.bowl)]
          ['iat' (sect:enjs:format now.bowl)]  ['amr' a+~[s+'Application']]
          ['scope' a+~[s+'api' s+'offline_access']]  ['device' s+device]
          ['sstamp' s+security-stamp]  ['jti' s+(token-id:v eny.bowl)]
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
          ['Kdf' (account-value 'kdf' n+'0')]  ['KdfIterations' (account-value 'kdfIterations' n+'600000')]
          ['KdfMemory' (opt:v account 'kdfMemory')]  ['KdfParallelism' (opt:v account 'kdfParallelism')]
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
      =/  data=exchange-request:c  [request (connect-client client) (~(got by fields) 'code') (~(got by fields) 'redirect_uri') (~(got by fields) 'code_verifier')]
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
  ++  account-value
    |=  [key=@t default=json]
    ^-  json
    =/  value  (opt:v account key)
    ?~  value  default
    value
  ++  kdf-data
    ^-  json
    (pairs:enjs:format ~[['kdfType' (account-value 'kdf' n+'0')] ['iterations' (account-value 'kdfIterations' n+'600000')] ['memory' (opt:v account 'kdfMemory')] ['parallelism' (opt:v account 'kdfParallelism')]])
  ++  key-salt
    ^-  json
    (account-value 'salt' (opt:v account 'email'))
  ++  security-stamp
    ^-  @t
    (str:v (account-value 'securityStamp' s+'connect-sso-v1'))
  ++  account-keys
    ^-  json
    =/  stored  (opt:v account 'accountKeys')
    ?^  stored  stored
    %-  pairs:enjs:format
    :~  ['publicKeyEncryptionKeyPair' (pairs:enjs:format ~[['wrappedPrivateKey' (opt:v account 'privateKey')] ['publicKey' (opt:v account 'publicKey')] ['Object' s+'publicKeyEncryptionKeyPair']])]
        ['Object' s+'privateKeys']
    ==
  ++  profile
    ^-  json
    %-  pairs:enjs:format
    :~  ['object' s+'profile']
        ['id' s+'00000000-0000-4000-8000-000000000001']
        ['name' ?:(=(~ (opt:v account 'name')) s+'Urbit vault' (opt:v account 'name'))]
        ['creationDate' (opt:v account 'creationDate')]
        ['email' (opt:v account 'email')]
        ['emailVerified' b+%.y]
        ['premium' b+%.y]
        ['premiumFromOrganization' b+%.n]
        ['masterPasswordHint' (opt:v account 'masterPasswordHint')]
        ['culture' ?:(=(~ (opt:v account 'culture')) s+'en-US' (opt:v account 'culture'))]
        ['twoFactorEnabled' b+%.n]
        ['key' (opt:v account 'key')]
        ['privateKey' (opt:v account 'privateKey')]
        ['accountKeys' account-keys]
        ['securityStamp' s+security-stamp]
        ['organizations' a+~]
        ['providers' a+~]
        ['forcePasswordReset' b+%.n]
        ['usesKeyConnector' b+%.n]
    ==
  ++  unlock-data
    ^-  json
    %-  pairs:enjs:format
    :~  ['Kdf' (pairs:enjs:format ~[['KdfType' (account-value 'kdf' n+'0')] ['Iterations' (account-value 'kdfIterations' n+'600000')] ['Memory' (opt:v account 'kdfMemory')] ['Parallelism' (opt:v account 'kdfParallelism')]])]
        ['MasterKeyEncryptedUserKey' (opt:v account 'key')]
        ['MasterKeyWrappedUserKey' (opt:v account 'key')]
        ['Salt' key-salt]
    ==
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
    =.  ciphers  (~(put by ciphers) id stored)
    =.  revision.state  next
    (reply rid 200 ?:(deleted ~ stored))
  ++  cipher-record
    |=  [id=@t data=json old=json stamp=json]
    ^-  json
    ?>  ?=([%o *] data)
    =/  stored=json  [%o (~(del by p.data) 'attachments2')]
    =.  stored  (put:v stored 'id' s+id)
    =.  stored  (put:v stored 'object' s+'cipherDetails')
    =.  stored  (put:v stored 'organizationId' ~)
    =.  stored  (put:v stored 'collectionIds' a+~)
    =.  stored  (put:v stored 'attachments' (attachment-list id))
    =.  stored  (put:v stored 'creationDate' ?~(old stamp (opt:v old 'creationDate')))
    =.  stored  (put:v stored 'revisionDate' stamp)
    =.  stored  (put:v stored 'deletedDate' (opt:v old 'deletedDate'))
    =.  stored  (put:v stored 'archivedDate' ?:((~(has by p.data) 'archivedDate') (opt:v data 'archivedDate') (opt:v old 'archivedDate')))
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
    ?.  (valid-cipher data folders)  (reply rid 400 ~)
    =/  known=json  (opt:v data 'lastKnownRevisionDate')
    ?:  &(!=(~ old) !=(~ known) !=(known (opt:v old 'revisionDate')))
      (reply rid 409 (pairs:enjs:format ~[['message' s+'Item changed; synchronize before editing.']]))
    =/  next=@da  (next-time:v now.bowl revision.state)
    =/  stamp=json  s+(iso:v next)
    =/  attachment-updates  (opt:v data 'attachments2')
    ?.  |(=(attachment-updates ~) ?=([%o *] attachment-updates))  (reply rid 400 ~)
    ::  Official clients can carry deleted attachments or clone-source metadata.
    ::  Ordinary saves update only this item's existing attachments; they never
    ::  copy a source blob into a clone. Full account rotation validates all IDs.
    =?  attachment-updates  ?=([%o *] attachment-updates)
      :-  %o
      %-  malt
      %+  skim  ~(tap by p.attachment-updates)
      |=  [p=@t q=json]
      =/  found  (~(get by attachments.state) p)
      ?~  found  |
      =(cipher.u.found id)
    =/  updated-attachments  (rewrap:va attachments.state id attachment-updates)
    ?~  updated-attachments  (reply rid 400 ~)
    =.  attachments.state  u.updated-attachments
    =/  stored=json  (cipher-record id data old stamp)
    =.  ciphers  (~(put by ciphers) id stored)
    =.  revision.state  next
    (reply rid 200 stored)
  ++  changed-account
    |=  [rid=@ta sid=@t updated=json]
    ^-  (quip card _this)
    ::  Connect is the authority. Authentication hashes in official request
    ::  models are deliberately not checked or retained in active vault state.
    =/  revoked=(list card)
      %+  turn  (skim ~(tap by sessions) |=([p=@t q=session] !=(p sid)))
      |=  [p=@t q=session]
      (revoke-card our.bowl p)
    =/  completed=(list card)
      (zing (turn ~(val by pending) |=([rid=@ta client=@t device=@t until=@da] (unavailable rid))))
    =.  account  (put:v updated 'securityStamp' s+(scot %uv (shas %security-stamp eny.bowl)))
    =.  sessions  (~(put by *(map @t session)) sid (~(got by sessions) sid))
    =.  cache.state  ~
    =.  pending  ~
    =.  downloads  ~
    =.  revision.state  (next-time:v now.bowl revision.state)
    =/  response  (reply rid 200 ~)
    [(weld revoked (weld completed -.response)) +.response]
  ++  change-password
    |=  [rid=@ta sid=@t data=json change-kdf=?]
    ^-  (quip card _this)
    =/  updated  (normalize-change:vk account data change-kdf)
    ?~  updated  (reply rid 400 (pairs:enjs:format ~[['message' s+'Invalid or inconsistent wrapped-key and KDF metadata.']]))
    (changed-account rid sid u.updated)
  ++  rotate-account
    |=  [rid=@ta sid=@t data=json]
    ^-  (quip card _this)
    =/  updated  (normalize-rotation:vk account data)
    ?~  updated  (reply rid 400 ~)
    =/  unlocking  (opt:v data 'accountUnlockData')
    ?.  (levy ^-((list @t) ~['emergencyAccessUnlockData' 'organizationAccountRecoveryUnlockData']) |=(name=@t |(=((opt:v unlocking name) ~) =((opt:v unlocking name) a+~))))  (reply rid 400 ~)
    =/  values  (opt:v data 'accountData')
    =/  items  (opt:v values 'ciphers')
    =/  directories  (opt:v values 'folders')
    ?.  &(?=([%a *] items) ?=([%a *] directories) |(=((opt:v values 'sends') ~) =((opt:v values 'sends') a+~)))  (reply rid 400 ~)
    =/  next  (next-time:v now.bowl revision.state)
    =/  stamp=json  s+(iso:v next)
    =/  dirs=(map @t json)  ~
    =/  rest=(list json)  p.directories
    =/  prepared=(unit (map @t json))
      |-
      ?~  rest  `dirs
      =/  id  (str:v (opt:v i.rest 'id'))
      ::  Older clients can include a null-ID folder placeholder.
      ?:  =(id '')  $(rest t.rest)
      ?.  (~(has by folders) id)  ~
      ?:  (~(has by dirs) id)  ~
      =/  name  (opt:v i.rest 'name')
      ?.  ?=([%s *] name)  ~
      $(rest t.rest, dirs (~(put by dirs) id (folder-record id name stamp)))
    ?~  prepared  (reply rid 400 ~)
    ?.  =(~(key by u.prepared) ~(key by folders))  (reply rid 409 ~)
    =.  dirs  u.prepared
    =/  vault=(map @t json)  ~
    =/  blobs=store:va  attachments.state
    =/  rest=(list json)  p.items
    =/  rotated=(unit [p=(map @t json) q=store:va])
      |-
      ?~  rest  `[vault blobs]
      =/  data=json  i.rest
      =/  id  (str:v (opt:v data 'id'))
      =/  old  (~(get by ciphers) id)
      ?~  old  ~
      ?:  (~(has by vault) id)  ~
      ?.  (valid-cipher data dirs)  ~
      =/  known  (opt:v data 'lastKnownRevisionDate')
      ?.  =(known (opt:v u.old 'revisionDate'))  ~
      =/  replacements  (opt:v data 'attachments2')
      =/  attached=(set @t)  (silt (turn (entries:va blobs id) |=([p=@t q=attachment:va] p)))
      =/  supplied=(set @t)  ?:(?=([%o *] replacements) ~(key by p.replacements) ~)
      ?.  =(attached supplied)  ~
      =/  changed  (rewrap:va blobs id replacements)
      ?~  changed  ~
      =.  blobs  u.changed
      =/  stored  (cipher-record id data u.old stamp)
      =.  stored  (put:v stored 'attachments' a+(turn (entries:va blobs id) |=([p=@t q=attachment:va] (metadata:va p q origin.state ~))))
      $(rest t.rest, vault (~(put by vault) id stored))
    ?~  rotated  (reply rid 409 (pairs:enjs:format ~[['message' s+'Vault changed or rotation is incomplete; sync before rotating keys.']]))
    ?.  =(~(key by p.u.rotated) ~(key by ciphers))  (reply rid 409 ~)
    ::  Commit only after every cipher, folder, attachment and key validates.
    =.  ciphers  p.u.rotated
    =.  folders  dirs
    =.  attachments.state  q.u.rotated
    (changed-account rid sid u.updated)
  ++  purge-vault
    |=  [rid=@ta data=json]
    ^-  (quip card _this)
    ?.  ?=([%o *] data)  (reply rid 400 ~)
    =.  ciphers  ~
    =.  folders  ~
    =.  attachments.state  ~
    =.  downloads  ~
    =.  revision.state  (next-time:v now.bowl revision.state)
    (reply rid 200 ~)
  ++  delete-account
    |=  [rid=@ta data=json]
    ^-  (quip card _this)
    ?.  ?=([%o *] data)  (reply rid 400 ~)
    =/  revoked=(list card)  (turn ~(tap by sessions) |=([p=@t q=session] (revoke-card our.bowl p)))
    =/  completed=(list card)  (zing (turn ~(val by pending) |=([rid=@ta client=@t device=@t until=@da] (unavailable rid))))
    =/  cancelled=(list card)
      ?~  trash-next.state  ~
      ~[[%pass /trash-cleanup/[(scot %da u.trash-next.state)] %arvo %b %rest u.trash-next.state]]
    =.  state  state(account ~, signing-key 0, sessions ~, ciphers ~, folders ~, cache ~, csrf ~, attachments ~, trash-next ~, revision now.bowl)
    =.  pending  ~
    =.  downloads  ~
    =/  response  (reply rid 200 ~)
    [(weld revoked (weld completed (weld cancelled -.response))) +.response]
  ++  valid-cipher
    |=  [data=json dirs=(map @t json)]
    ^-  ?
    ?.  ?=([%o *] data)  |
    ?.  ?=([%s *] (opt:v data 'name'))  |
    ?:  |(!=(~ (opt:v data 'organizationId')) !=(~ (opt:v data 'organizationID')))  |
    =/  kind  (opt:v data 'type')
    ?.  ?=([%n *] kind)  |
    ?.  (~(has in (silt ~[n+'1' n+'2' n+'3' n+'4' n+'5' n+'6' n+'7' n+'8'])) kind)  |
    =/  archive  (opt:v data 'archivedDate')
    ?.  |(=(~ archive) &(?=([%s *] archive) ?=(^ (stud:chrono:userlib (str:v archive)))))  |
    =/  folder  (opt:v data 'folderId')
    ?~  folder  &
    ?.  ?=([%s *] folder)  |
    |(=(p.folder '') (~(has by dirs) p.folder))
  ++  item-list
    |=  values=(list json)
    ^-  json
    (pairs:enjs:format ~[['object' s+'list'] ['data' a+values] ['continuationToken' ~]])
  ++  bulk-ciphers
    |=  [rid=@ta action=@tas data=json]
    ^-  (quip card _this)
    =/  values  (opt:v data 'ids')
    ?.  ?=([%a *] values)  (reply rid 400 ~)
    ?.  (levy p.values |=(value=json ?=([%s *] value)))  (reply rid 400 ~)
    =/  ids=(set @t)  (silt (turn p.values str:v))
    ?.  (levy ~(tap in ids) |=(id=@t (~(has by ciphers) id)))  (reply rid 404 ~)
    =/  folder  (opt:v data 'folderId')
    ?.  |(!=(%move action) =(folder ~) &(?=([%s *] folder) |(=(folder s+'') (~(has by folders) (str:v folder)))))  (reply rid 400 ~)
    =/  next  (next-time:v now.bowl revision.state)
    =/  stamp=json  s+(iso:v next)
    =/  remaining=(list @t)  ~(tap in ids)
    =/  candidate  ciphers
    =/  changed=(list json)  ~
    |-
    ?~  remaining
      =.  ciphers  candidate
      =?  attachments.state  ?=(%hard action)
        (malt (skim ~(tap by attachments.state) |=([p=@t q=attachment:va] !(~(has in ids) cipher.q))))
      =?  downloads  ?=(%hard action)
        (malt (skim ~(tap by downloads) |=([p=@t q=[sid=@t cipher=@t attachment=@t until=@da]] !(~(has in ids) cipher.q))))
      =?  revision.state  ?=(^ changed)  next
      ?:  ?=(%hard action)
        =?  revision.state  ?=(^ p.values)  next
        (reply rid 200 ~)
      (reply rid 200 ?:((~(has in (silt ^-((list @tas) ~[%restore %archive %unarchive]))) action) (item-list (flop changed)) ~))
    =/  id  i.remaining
    =/  old  (~(got by candidate) id)
    ?:  ?=(%hard action)
      $(remaining t.remaining, candidate (~(del by candidate) id))
    =/  updated=json
      ?+  action  ~|(%invalid-bulk-action !!)
        %move       (put:v old 'folderId' ?:(=(folder s+'') ~ folder))
        %trash      (put:v old 'deletedDate' ?:(=(~ (opt:v old 'deletedDate')) stamp (opt:v old 'deletedDate')))
        %restore    (put:v old 'deletedDate' ~)
        %archive    (put:v old 'archivedDate' ?:(=(~ (opt:v old 'archivedDate')) stamp (opt:v old 'archivedDate')))
        %unarchive  (put:v old 'archivedDate' ~)
      ==
    =.  updated  (put:v updated 'revisionDate' stamp)
    $(remaining t.remaining, candidate (~(put by candidate) id updated), changed [updated changed])
  ++  partial-cipher
    |=  [rid=@ta id=@t data=json]
    ^-  (quip card _this)
    =/  old  (~(get by ciphers) id)
    ?~  old  (reply rid 404 ~)
    =/  folder  (opt:v data 'folderId')
    ?.  |(=(folder ~) &(?=([%s *] folder) |(=(folder s+'') (~(has by folders) (str:v folder)))))  (reply rid 400 ~)
    =/  favorite  (opt:v data 'favorite')
    ?.  ?=([%b *] favorite)  (reply rid 400 ~)
    =/  known  (opt:v data 'lastKnownRevisionDate')
    ?:  &(!=(~ known) !=(known (opt:v u.old 'revisionDate')))  (reply rid 409 ~)
    =/  next  (next-time:v now.bowl revision.state)
    =/  updated  (put:v (put:v u.old 'folderId' ?:(=(folder s+'') ~ folder)) 'favorite' favorite)
    =.  updated  (put:v updated 'revisionDate' s+(iso:v next))
    =.  ciphers  (~(put by ciphers) id updated)
    =.  revision.state  next
    (reply rid 200 updated)
  ++  archive-cipher
    |=  [rid=@ta id=@t archived=?]
    ^-  (quip card _this)
    =/  old  (~(get by ciphers) id)
    ?~  old  (reply rid 404 ~)
    =/  next  (next-time:v now.bowl revision.state)
    =/  stored  (put:v u.old 'archivedDate' ?:(archived s+(iso:v next) ~))
    =.  stored  (put:v stored 'revisionDate' s+(iso:v next))
    =.  ciphers  (~(put by ciphers) id stored)
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
  ++  save-folder
    |=  [rid=@ta id=@t data=json]
    ^-  (quip card _this)
    =/  name  (opt:v data 'name')
    ?.  ?=([%s *] name)  (reply rid 400 ~)
    =/  next=@da  (next-time:v now.bowl revision.state)
    =/  stored  (folder-record id name s+(iso:v next))
    =.  folders  (~(put by folders) id stored)
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
      =.  dirs  (~(put by dirs) id stored)
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
      ?.  (valid-cipher linked dirs)  [400 vault number]
      =/  stored=json  (cipher-record id linked ~ stamp)
      $(cipher-list t.cipher-list, cipher-index +(cipher-index), vault (~(put by vault) id stored))
    ?.  =(200 status.imported)  (reply rid status.imported ~)
    =.  folders  dirs
    =.  ciphers  vault.imported
    =.  serial.state  number.imported
    =.  revision.state  next
    (reply rid 200 ~)
  ++  domain-settings
    |=  omit-excluded=?
    ^-  json
    =/  custom  (opt:v account 'equivalentDomains')
    =?  custom  =(~ custom)  a+~
    =/  ignored  (opt:v account 'excludedGlobalEquivalentDomains')
    =?  ignored  =(~ ignored)  a+~
    ?>  ?=([%a *] ignored)
    =/  ids=(set json)  (silt p.ignored)
    =/  globals
      %+  turn  defaults:vd
      |=  value=json
      (put:v value 'excluded' b+(~(has in ids) (opt:v value 'type')))
    =?  globals  omit-excluded
      (skim globals |=(value=json =((opt:v value 'excluded') b+%.n)))
    (pairs:enjs:format ~[['object' s+'domains'] ['equivalentDomains' custom] ['globalEquivalentDomains' a+globals]])
  ++  save-domains
    |=  [rid=@ta data=json]
    ^-  (quip card _this)
    ?.  ?=([%o *] data)  (reply rid 400 ~)
    =/  custom  (opt:v data 'equivalentDomains')
    =/  ignored  (opt:v data 'excludedGlobalEquivalentDomains')
    =?  custom  =(~ custom)  a+~
    =?  ignored  =(~ ignored)  a+~
    ?.  &(?=([%a *] custom) ?=([%a *] ignored))  (reply rid 400 ~)
    =/  valid-group
      |=  group=json
      ^-  ?
      ?.  ?=([%a *] group)  |
      (levy p.group |=(domain=json &(?=([%s *] domain) !=('' (str:v domain)))))
    ?.  (levy p.custom valid-group)  (reply rid 400 ~)
    ?.  (levy p.ignored |=(id=json ?.(?=([%n *] id) | ?=(^ (rush p.id dem)))))  (reply rid 400 ~)
    =/  updated  (put:v (put:v account 'equivalentDomains' custom) 'excludedGlobalEquivalentDomains' ignored)
    =.  account  updated
    =.  revision.state  (next-time:v now.bowl revision.state)
    (reply rid 200 o+~)
  ++  save-vault-settings
    |=  [rid=@ta data=json]
    ^-  (quip card _this)
    ?.  ?=([%o *] data)  (reply rid 400 ~)
    ?.  (~(has by p.data) 'trashAutoDeleteDays')  (reply rid 400 ~)
    =/  value  (opt:v data 'trashAutoDeleteDays')
    ?.  |(=(~ value) ?=([%n *] value))  (reply rid 400 ~)
    =/  days=(unit @ud)
      ?.  ?=([%n *] value)  ~
      (rush p.value dem)
    ?:  &(!=(~ value) |(=(~ days) ?~(days & =(0 u.days))))  (reply rid 400 ~)
    ::  Enabling deletion is an explicit operator choice, never a default.
    ?:  &(!=(~ value) !=((opt:v data 'confirmAutoDelete') b+%.y))  (reply rid 400 ~)
    =/  cancelled=(list card)
      ?~  trash-next.state  ~
      ~[[%pass /trash-cleanup/[(scot %da u.trash-next.state)] %arvo %b %rest u.trash-next.state]]
    =.  account  (put:v account 'trashAutoDeleteDays' value)
    =.  trash-next.state  ?~(value ~ `(add now.bowl ~d1))
    =.  this  expire-trash
    =.  revision.state  (next-time:v now.bowl revision.state)
    =/  result  (reply rid 200 (pairs:enjs:format ~[['object' s+'vaultSettings'] ['trashAutoDeleteDays' value]]))
    [(weld cancelled (weld trash-cards -.result)) +.result]
  ++  save-profile
    |=  [rid=@ta data=json]
    ^-  (quip card _this)
    ?.  ?=([%o *] data)  (reply rid 400 ~)
    =/  name  (opt:v data 'name')
    =/  culture  (opt:v data 'culture')
    ?.  &(|(=(name ~) ?=([%s *] name)) ?=([%s *] culture))  (reply rid 400 ~)
    =.  account  (put:v (put:v account 'name' name) 'culture' culture)
    =.  revision.state  (next-time:v now.bowl revision.state)
    (reply rid 200 profile)
  ++  vault-summary
    ^-  json
    =/  values=(list json)  ~(val by ciphers)
    =/  active=(list json)  (skim values |=(item=json =(~ (opt:v item 'deletedDate'))))
    =/  blobs=(list attachment:va)  (skim ~(val by attachments.state) |=(item=attachment:va ?=(^ content.item)))
    %-  pairs:enjs:format
    :~  ['items' (numb:enjs:format (lent active))]
        ['trashed' (numb:enjs:format (sub (lent values) (lent active)))]
        ['archived' (numb:enjs:format (lent (skim active |=(item=json !=(~ (opt:v item 'archivedDate'))))))]
        ['folders' (numb:enjs:format (lent ~(tap by folders)))]
        ['attachments' (numb:enjs:format (lent blobs))]
        ['attachmentBytes' (numb:enjs:format (roll blobs |=([item=attachment:va size=@ud] (add size expected.item))))]
        ['revision' s+(iso:v revision.state)]
    ==
  ++  handle
    |=  [rid=@ta req=inbound-request:eyre]
    ^-  (quip card _this)
    =/  original  (head (split:v '?' url.request.req))
    =/  prefix  '/apps/urbitwarden'
    ?.  |(=(original prefix) =((cat 3 prefix '/') (crip (scag +((met 3 prefix)) (trip original)))))
      (reply rid 404 ~)
    =/  local-url  (crip (slag (met 3 prefix) (trip url.request.req)))
    =.  req  req(url.request ?:(=('' (head (split:v '?' local-url))) (cat 3 '/' local-url) local-url))
    =/  url  (head (split:v '?' url.request.req))
    =/  method  method.request.req
    =/  headers  header-list.request.req
    =/  payload  ?~(body.request.req '' q.u.body.request.req)
    ?:  =(%'OPTIONS' method)  (reply rid 200 ~)
    =/  icon-path  (stab url)
    ?:  ?=([%icons @ %'icon.png' ~] icon-path)
      (website-icon rid i.t.icon-path method)
    =/  asset  (~(get by assets:assets) url)
    ?:  ?=(^ asset)
      ?.  =(method %'GET')  (reply rid 405 ~)
      ?.  &(authenticated.req =(src.bowl our.bowl))
        ?:  =('text/html; charset=utf-8' mime.u.asset)  (login-redirect rid)
        (reply rid 401 ~)
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
        (reply rid 200 (pairs:enjs:format ~[['csrf' s+csrf] ['enrolled' b+!=(account ~)] ['summary' vault-summary] ['email' (opt:v account 'email')] ['webVaultURL' s+(service-origin (cat 3 'https://' (fall (get-header:http 'host' headers) '')))]]))
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
      =.  state  state(account (put:v (put:v data 'creationDate' s+(iso:v now.bowl)) 'securityStamp' s+(scot %uv (shas %security-stamp eny.bowl))), origin (service-origin origin), signing-key (shas %vault-sign eny.bowl), revision now.bowl)
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
      ?>  (~(has in (silt ~['cli' 'browser' 'desktop' 'mobile'])) (~(got by args) 'client_id'))
      =/  keys  ~['client_id' 'redirect_uri' 'response_type' 'scope' 'state' 'code_challenge' 'code_challenge_method']
      =/  query
        %-  crip
        %-  zing
        %+  join  "&"
        %+  turn  keys
        |=  key=@t
        "{(trip key)}={(en-urlt:html (trip (~(got by args) key)))}"
      ::  Owner-authenticated browser setup registers only the requested client,
      ::  then starts Connect consent with its namespaced registration ID.
      (redirect rid (cat 3 '/apps/urbitwarden/#/connect?' query))
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
      =/  env  (pairs:enjs:format ~[['vault' s+base] ['api' s+(cat 3 base '/api')] ['identity' s+(cat 3 base '/identity')] ['notifications' s+(cat 3 base '/notifications')] ['icons' s+(cat 3 base '/icons')] ['sso' s+(cat 3 base '/identity')] ['cloudRegion' ~]])
      (reply rid 200 (pairs:enjs:format ~[['object' s+'config'] ['version' s+'2026.6.0'] ['server' (pairs:enjs:format ~[['name' s+'Urbitwarden backend'] ['url' s+base]])] ['environment' env] ['featureStates' (pairs:enjs:format ~[['pm-19148-innovation-archive' b+%.y]])] ['settings' (pairs:enjs:format ~[['disableUserRegistration' b+%.y]])]]))
    ?:  =('/api/devices/knowndevice' url)  (reply rid 200 b+%.n)
    ?:  =('/api/organizations/domain/sso/details' url)
      (reply rid 200 (pairs:enjs:format ~[['object' s+'list'] ['data' a+~] ['continuationToken' ~]]))
    =/  attachment-path  (stab url)
    ?:  ?=([%attachments @ @ ~] attachment-path)
      (download-attachment rid i.t.attachment-path i.t.t.attachment-path req)
    =/  auth  (fall (get-header:http 'authorization' headers) '')
    ?.  =("Bearer " (scag 7 (trip auth)))  (reply rid 401 ~)
    =/  digest  (shax (crip (slag 7 (trip auth))))
    =/  found  (skim ~(tap by sessions) |=([p=@t q=session] &(=(digest access.q) (lth now.bowl expires.q))))
    ?~  found  (reply rid 401 ~)
    ?:  =(~ (grant p.i.found))  (reply rid 401 ~)
    ?:  |(=('/api/accounts/password' url) =('/api/accounts/kdf' url))
      ?.  =(%'POST' method)  (reply rid 405 ~)
      (change-password rid p.i.found (need (de:json:html payload)) =('/api/accounts/kdf' url))
    ?:  =('/api/accounts/key-management/rotate-user-account-keys' url)
      ?.  =(%'POST' method)  (reply rid 405 ~)
      (rotate-account rid p.i.found (need (de:json:html payload)))
    ?:  |(=('/api/accounts' url) =('/api/accounts/delete' url))
      ?.  |(&(=('/api/accounts' url) =(%'DELETE' method)) &(=('/api/accounts/delete' url) =(%'POST' method)))  (reply rid 405 ~)
      (delete-account rid (need (de:json:html payload)))
    ?:  =('/api/ciphers/purge' url)
      ?.  =(%'POST' method)  (reply rid 405 ~)
      =/  parts  (split:v '?' url.request.req)
      =/  args  (form ?~(parts '' ?~(t.parts '' i.t.parts)))
      ?:  !=('' (~(gut by args) 'organizationId' ''))  (reply rid 400 ~)
      (purge-vault rid (need (de:json:html payload)))
    ?:  =('/api/accounts/verify-password' url)
      (reply rid 400 (pairs:enjs:format ~[['error' s+'connect_authorization_required'] ['message' s+'This vault authorizes management through Connect; server password verification is unavailable.']]))
    ?:  =('/api/accounts/keys' url)
      ?.  =(%'GET' method)  (reply rid 405 ~)
      (reply rid 200 (pairs:enjs:format ~[['object' s+'keys'] ['key' (opt:v account 'key')] ['privateKey' (opt:v account 'privateKey')] ['publicKey' (opt:v account 'publicKey')] ['accountKeys' account-keys]]))
    ?:  =('/api/accounts/key-management/user-key-id' url)
      ?.  =(%'POST' method.request.req)  (reply rid 405 ~)
      =/  data=json  (need (de:json:html ?~(body.request.req '{}' q.u.body.request.req)))
      =.  account  (put:v account 'userKeyId' (get:v data 'userKeyId'))
      (reply rid 200 ~)
    ?:  =('/api/accounts/profile' url)
      ?:  =(%'GET' method)  (reply rid 200 profile)
      ?.  |(=(%'PUT' method) =(%'POST' method))  (reply rid 405 ~)
      (save-profile rid (need (de:json:html payload)))
    ?:  =('/api/settings/vault' url)
      ?:  =(%'GET' method)
        (reply rid 200 (pairs:enjs:format ~[['object' s+'vaultSettings'] ['trashAutoDeleteDays' (opt:v account 'trashAutoDeleteDays')]]))
      ?.  |(=(%'PUT' method) =(%'POST' method))  (reply rid 405 ~)
      (save-vault-settings rid (need (de:json:html payload)))
    ?:  =('/api/settings/domains' url)
      ?:  =(%'GET' method)  (reply rid 200 (domain-settings |))
      ?.  |(=(%'PUT' method) =(%'POST' method))  (reply rid 405 ~)
      (save-domains rid (need (de:json:html payload)))
    ?:  =('/api/accounts/revision-date' url)  (reply rid 200 (time:enjs:format revision.state))
    ?:  =('/api/sync' url)
      %^  reply  rid  200
      %-  pairs:enjs:format
      :~  ['object' s+'sync']
          ['profile' profile]
          ['userDecryption' (pairs:enjs:format ~[['userKeyId' (opt:v account 'userKeyId')] ['masterPasswordUnlock' (pairs:enjs:format ~[['kdf' kdf-data] ['masterKeyWrappedUserKey' (opt:v account 'key')] ['masterKeyEncryptedUserKey' (opt:v account 'key')] ['salt' key-salt]])]])]
          ['ciphers' a+~(val by ciphers)]
          ['folders' a+~(val by folders)]
          ['collections' a+~]
          ['policies' a+~]
          ['sends' a+~]
          ['domains' (domain-settings &)]
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
        [%api %ciphers id=@ta %attachment %v2 ~]
      ?.  =(%'POST' method)  (reply rid 405 ~)
      (prepare-attachment rid i.t.t.path data)
        [%api %ciphers id=@ta %attachment aid=@ta ~]
      (attachment-request rid i.t.t.path i.t.t.t.t.path p.i.found req)
        [%api %ciphers id=@ta %attachment aid=@ta %delete ~]
      ?.  =(%'POST' method)  (reply rid 405 ~)
      (delete-attachment rid i.t.t.path i.t.t.t.t.path)
        [%api %ciphers %move ~]
      ?.  |(=(%'PUT' method) =(%'POST' method))  (reply rid 405 ~)
      (bulk-ciphers rid %move data)
        [%api %ciphers %delete ~]
      ?.  |(=(%'PUT' method) =(%'POST' method))  (reply rid 405 ~)
      (bulk-ciphers rid ?:(=(%'PUT' method) %trash %hard) data)
        [%api %ciphers %restore ~]
      ?.  =(%'PUT' method)  (reply rid 405 ~)
      (bulk-ciphers rid %restore data)
        [%api %ciphers %archive ~]
      ?.  =(%'PUT' method)  (reply rid 405 ~)
      (bulk-ciphers rid %archive data)
        [%api %ciphers %unarchive ~]
      ?.  =(%'PUT' method)  (reply rid 405 ~)
      (bulk-ciphers rid %unarchive data)
        [%api %ciphers id=@ta %details ~]
      ?.  =(%'GET' method)  (reply rid 405 ~)
      =/  old  (~(get by ciphers) i.t.t.path)
      ?~  old  (reply rid 404 ~)
      (reply rid 200 u.old)
        [%api %ciphers id=@ta %partial ~]
      ?.  |(=(%'PUT' method) =(%'POST' method))  (reply rid 405 ~)
      (partial-cipher rid i.t.t.path data)
        [%api %ciphers id=@ta %archive ~]
      ?.  =(%'PUT' method)  (reply rid 405 ~)
      (archive-cipher rid i.t.t.path &)
        [%api %ciphers id=@ta %unarchive ~]
      ?.  =(%'PUT' method)  (reply rid 405 ~)
      (archive-cipher rid i.t.t.path |)
        [%api %ciphers %import ~]
      ?.  =(%'POST' method)  (reply rid 405 ~)
      (import-vault rid data)
        [%api %ciphers ~]
      ?:  =(%'DELETE' method)  (bulk-ciphers rid %hard data)
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
      (bulk-ciphers rid %hard (pairs:enjs:format ~[['ids' a+~[s+i.t.t.path]]]))
        [%api %ciphers id=@ta %delete ~]
      ?:  =(%'POST' method)  (bulk-ciphers rid %hard (pairs:enjs:format ~[['ids' a+~[s+i.t.t.path]]]))
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
  ?:  ?=([%trash-cleanup @ ~] wire)
    ?>  ?=([%behn %wake *] sign-arvo)
    =/  scheduled  trash-next.state
    ?~  scheduled  `this
    ?.  =(i.t.wire (scot %da u.scheduled))  `this
    =.  this  expire-trash
    =.  trash-next.state  ?~(trash-retention ~ `(add now.bowl ~d1))
    [trash-cards this]
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
