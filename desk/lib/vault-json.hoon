::  Wire helpers. Encrypted fields remain opaque JSON.
/+  jose
|%
++  token-id
  |=  seed=@
  ^-  @t
  (scot %uv (shas %token-id seed))
++  get
  |=  [obj=json key=@t]
  ^-  json
  ?.  ?=([%o *] obj)  ~
  (~(got by p.obj) key)
++  opt
  |=  [obj=json key=@t]
  ^-  json
  ?.  ?=([%o *] obj)  ~
  (~(gut by p.obj) key ~)
++  str
  |=  val=json
  ^-  @t
  ?~  val  ''
  ?.  ?=([%s *] val)  ''
  p.val
++  put
  |=  [obj=json key=@t val=json]
  ^-  json
  ?>  ?=([%o *] obj)
  [%o (~(put by p.obj) key val)]
++  split
  |=  [delim=@ text=@t]
  ^-  (list @t)
  =/  left=tape  (trip text)
  =/  part=tape  ~
  =/  out=(list @t)  ~
  |-
  ?~  left  (flop [(crip (flop part)) out])
  ?:  =(delim i.left)
    $(left t.left, part ~, out [(crip (flop part)) out])
  $(left t.left, part [i.left part])
++  decode
  |=  text=@t
  ^-  @t
  =/  tap=tape  (turn (trip text) |=(c=@ ?:(=('+' c) ' ' c)))
  (crip (need (de-urlt:html tap)))
++  form
  |=  text=@t
  ^-  (map @t @t)
  =/  chunks=(list @t)  (split '&' text)
  =/  out=(map @t @t)  ~
  |-
  ?~  chunks  out
  =/  parts=(list @t)  (split '=' i.chunks)
  ?>  ?=(^ parts)
  =/  key=@t  (decode i.parts)
  =/  val=@t  (decode ?~(t.parts '' i.t.parts))
  $(chunks t.chunks, out (~(put by out) key val))
++  b64
  |=  txt=@t
  (en-base64url:jose [(met 3 txt) txt])
++  jwt
  |=  [claims=json key=@]
  ^-  @t
  =/  head=@t  (b64 '{"alg":"HS256","typ":"JWT"}')
  =/  body=@t  (b64 (en:json:html claims))
  =/  input=@t  (rap 3 ~[head '.' body])
  =/  sig=@  (hmac-sha256l:hmac:crypto [32 (rev 3 32 key)] [(met 3 input) (rev 3 (met 3 input) input)])
  (rap 3 ~[input '.' (en-base64url:jose [32 (rev 3 32 sig)])])
++  decimal
  |=  num=@ud
  ^-  @t
  =/  n=json  (numb:enjs:format num)
  ?>  ?=([%n *] n)
  p.n
++  two
  |=  num=@ud
  ^-  @t
  (cat 3 ?:(=(0 (div num 10)) '0' '') (decimal num))
++  three
  |=  num=@ud
  ^-  @t
  =/  digits=@t  (decimal num)
  (cat 3 (crip (reap (sub 3 (met 3 digits)) '0')) digits)
++  next-time
  |=  [now=@da previous=@da]
  ^-  @da
  (max now (from-unix-ms:chrono:userlib +((unm:chrono:userlib previous))))
++  iso
  |=  now=@da
  ^-  @t
  =/  d=date  (yore now)
  (rap 3 ~[(decimal y.d) '-' (two m.d) '-' (two d.t.d) 'T' (two h.t.d) ':' (two m.t.d) ':' (two s.t.d) '.' (three (mod (unm:chrono:userlib now) 1.000)) 'Z'])
++  uuid
  |=  n=@ud
  ^-  @t
  =/  digits=@t  (decimal n)
  =/  pad=@t  (crip (reap (sub 12 (met 3 digits)) '0'))
  (rap 3 ~['00000000-0000-4000-8000-' pad digits])
--
