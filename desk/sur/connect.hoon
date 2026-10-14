::  Stable protocol and durable generic store types. No application schema.
|%
+$  key  [collection=@t id=@t]
+$  record  [=key data=json revision=@ud updated=@da]
+$  operation
  $%  [%put =key data=json expected=(unit @ud)]
      [%delete =key expected=@ud]
  ==
+$  mutation  [id=@t digest=@ux operations=(list operation)]
+$  receipt  [digest=@ux expires=@da result=json]
+$  tombstone  [revision=@ud expires=@da]
+$  batch  [revision=@ud changes=(list json) bytes=@ud]
+$  space
  $:  epoch=@ud
      revision=@ud
      records=(map key record)
      tombstones=(map key tombstone)
      receipts=(map @t receipt)
      journal=(list batch)
      bytes=@ud
  ==
+$  authority  [namespace=@t epoch=@ud read=? write=? delete=?]
+$  outcome  [status=@ud body=json]
+$  transition  [next=space =outcome]
::  Credentials are represented only by digests in persisted state.
+$  client
  [id=@t name=@t redirect=@t namespace=@t enabled=? created=@da]
+$  authorization
  $:  id=@t  client=@t  redirect=@t  namespace=@t  epoch=@ud  scopes=(set @t)
      challenge=@t  state=@t  label=@t  expires=@da
  ==
+$  code  [authorization=authorization expires=@da]
+$  session
  $:  id=@t  client=@t  namespace=@t  epoch=@ud  scopes=(set @t)  label=@t
      access=@ux  access-expires=@da  refresh=@ux  consumed=(set @ux)
      created=@da  expires=@da  minute=@ud  requests=@ud
  ==
+$  auth-state
  $:  clients=(map @t client)
      pending=(map @t authorization)
      codes=(map @ux code)
      sessions=(map @t session)
      starts=(map @t [minute=@ud count=@ud])
  ==
+$  auth-result  [next=auth-state =outcome]
+$  snapshot
  [id=@t session=@t namespace=@t global=@ud epoch=@ud revision=@ud expires=@da records=(list record)]
+$  csrf  [token=@ux expires=@da]
+$  state-0  [%0 instance=@t]
+$  state-1
  $:  %1  instance=@t  issuer=@t  epoch=@ud  nonce=@ud  auth=auth-state
      spaces=(map @t space)  csrf=(map @ux csrf)
  ==
::  An opt-in, immutable local resource policy; no document scopes.
+$  integration  [agent=@tas scopes=(set @t) redirects=(set @t)]
+$  state-2
  $:  %2  instance=@t  issuer=@t  epoch=@ud  nonce=@ud  auth=auth-state
      spaces=(map @t space)  csrf=(map @ux csrf)
      integrations=(map @t integration)
  ==
+$  exchange-request
  [request=@t client=@t code=@t redirect=@t verifier=@t]
+$  revoke-request  [resource=@tas session=@t]
::  Transient HTTP state is intentionally excluded from +on-save.
+$  poll  [rid=@ta session=@t namespace=@t after=@t limit=@ud access=@ux source=@p deadline=@da]
+$  world
  [state=state-2 snapshots=(map @t snapshot) polls=(map @ta poll)]
+$  context
  [our=@p source=@p now=@da entropy=@uv rid=@ta local=? development=? request=inbound-request:eyre]
+$  http-result  [next=world payload=(unit simple-payload:http)]
--
