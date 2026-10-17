::  Opaque encrypted attachments. No file names or keys are decrypted here.
::  Structural wire molds keep this library independent of Gall and its state.
|%
+$  octs  [p=@ud q=@]
+$  json
  $@  ~
  $%  [%a p=(list json)]
      [%b p=?]
      [%o p=(map @t json)]
      [%n p=@ta]
      [%s p=@t]
  ==
+$  attachment
  [cipher=@t filename=@t key=@t expected=@ud content=(unit octs)]
+$  store  (map @t attachment)
+$  headers  (list [p=@t q=@t])
++  decimal
  |=  number=@ud
  ^-  @t
  (crip (skim (trip (scot %ud number)) |=(ch=@tD !=(ch '.'))))
++  metadata
  |=  [id=@t value=attachment origin=@t download=(unit @t)]
  ^-  json
  [%o (malt ~[['id' s+id] ['url' s+(fall download (rap 3 ~[origin '/attachments/' cipher.value '/' id]))] ['fileName' s+filename.value] ['key' s+key.value] ['size' s+(decimal expected.value)] ['sizeName' s+(cat 3 (decimal expected.value) ' B')] ['object' s+'attachment']])]
++  entries
  |=  [values=store cipher=@t]
  ^-  (list [p=@t q=attachment])
  %+  sort
    (skim ~(tap by values) |=([p=@t q=attachment] =(cipher cipher.q)))
  |=  [a=[p=@t q=attachment] b=[p=@t q=attachment]]
  (aor p.a p.b)
++  remove-cipher
  |=  [values=store cipher=@t]
  ^-  store
  (malt (skim ~(tap by values) |=([p=@t q=attachment] !=(cipher cipher.q))))
++  complete
  |=  [value=attachment body=octs]
  ^-  (unit attachment)
  ?.  &(=(p.body expected.value) (lte (met 3 q.body) p.body))  ~
  ?^  content.value
    ?.  =(u.content.value body)  ~
    `value
  `value(content `body)
++  text-field
  |=  [value=json name=@t]
  ^-  (unit @t)
  ?.  ?=([%o *] value)  ~
  =/  field  (~(get by p.value) name)
  ?~  field  ~
  ?.  ?=([%s *] u.field)  ~
  ?:  =(p.u.field '')  ~
  `p.u.field
++  rewrap
  |=  [values=store cipher=@t updates=json]
  ^-  (unit store)
  ?~  updates  `values
  ?.  ?=([%o *] updates)  ~
  =/  rows  ~(tap by p.updates)
  |-
  ?~  rows  `values
  =/  found  (~(get by values) p.i.rows)
  ?~  found  ~
  ?.  =(cipher cipher.u.found)  ~
  =/  name  (text-field q.i.rows 'fileName')
  =/  key  (text-field q.i.rows 'key')
  ?~  name  ~
  ?~  key  ~
  $(rows t.rows, values (~(put by values) p.i.rows u.found(filename u.name, key u.key)))
++  lower
  |=  text=@t
  ^-  @t
  %-  crip
  %+  turn  (trip text)
  |=  ch=@tD
  ?:(&((gte ch 'A') (lte ch 'Z')) (add ch 32) ch)
++  trim
  |=  text=@t
  ^-  @t
  =/  chars  (trip text)
  =/  strip
    |=  chars=tape
    ^-  tape
    |-
    ?~  chars  ~
    ?.  |(=(i.chars ' ') =(i.chars 9))  chars
    $(chars t.chars)
  (crip (flop (strip (flop (strip chars)))))
++  split-first
  |=  [delimiter=@t text=@t]
  ^-  (unit [p=@t q=@t])
  =/  left=tape  ~
  =/  chars  (trip text)
  |-
  ?~  chars  ~
  ?:  =(i.chars delimiter)  `[(crip (flop left)) (crip t.chars)]
  $(chars t.chars, left [i.chars left])
++  split
  |=  [delimiter=@t text=@t]
  ^-  (list @t)
  =/  rows=(list @t)  ~
  |-
  =/  part  (split-first delimiter text)
  ?~  part  (flop [text rows])
  $(text q.u.part, rows [p.u.part rows])
++  token
  |=  text=@t
  ^-  ?
  =/  chars  (trip text)
  ?~  chars  |
  (levy ^-(tape chars) |=(ch=@tD |(&((gte ch 'a') (lte ch 'z')) &((gte ch 'A') (lte ch 'Z')) &((gte ch '0') (lte ch '9')) (lien "!#$%&'*+-.^_`|~" |=(allowed=@tD =(ch allowed))))))
++  unquote
  |=  text=@t
  ^-  (unit @t)
  =/  chars  (trip text)
  ?~  chars  ~
  ?.  =(i.chars '"')  ?:((token text) `text ~)
  ?.  &((gte (lent chars) 2) =((rear chars) '"'))  ~
  =/  inner  (scag (sub (lent chars) 2) t.chars)
  ?.  (levy inner |=(ch=@tD &((gte ch 32) (lte ch 126) !=(ch '"') !=(ch 92))))  ~
  `(crip inner)
++  parameters
  |=  text=@t
  ^-  (unit [kind=@t params=(map @t @t)])
  =/  parts  (split ';' text)
  ?~  parts  ~
  =/  kind  (lower (trim i.parts))
  =/  params=(map @t @t)  ~
  =/  tail  t.parts
  |-
  ?~  tail  `[kind params]
  =/  pair  (split-first '=' (trim i.tail))
  ?~  pair  ~
  =/  key  (lower (trim p.u.pair))
  ?.  &((token key) !(~(has by params) key))  ~
  =/  value  (unquote (trim q.u.pair))
  ?~  value  ~
  $(tail t.tail, params (~(put by params) key u.value))
++  one-header
  |=  [fields=headers name=@t]
  ^-  (unit @t)
  =/  found=(unit @t)  ~
  |-
  ?~  fields  found
  ?.  =((lower p.i.fields) name)  $(fields t.fields)
  ?^  found  ~
  $(fields t.fields, found `q.i.fields)
++  boundary
  |=  fields=headers
  ^-  (unit @t)
  =/  header  (one-header fields 'content-type')
  ?~  header  ~
  =/  parsed  (parameters u.header)
  ?~  parsed  ~
  ?.  =(kind.u.parsed 'multipart/form-data')  ~
  =/  value  (~(get by params.u.parsed) 'boundary')
  ?~  value  ~
  =/  chars  (trip u.value)
  ::  MIME boundary grammar (RFC 2046), not a file-size quota.
  ?.  &((gth (lent chars) 0) (lte (lent chars) 70))  ~
  ?:  =((rear chars) ' ')  ~
  ?.  (levy ^-(tape chars) |=(ch=@tD |(&((gte ch 'a') (lte ch 'z')) &((gte ch 'A') (lte ch 'Z')) &((gte ch '0') (lte ch '9')) (lien "'()+_,-./:=? " |=(allowed=@tD =(ch allowed))))))  ~
  value
++  find
  |=  [needle=@t body=octs offset=@ud]
  ^-  (unit @ud)
  =/  width  (met 3 needle)
  |-
  ?:  (gth (add offset width) p.body)  ~
  ?:  =(needle (cut 3 [offset width] q.body))  `offset
  $(offset +(offset))
++  part-headers
  |=  text=@t
  ^-  (unit headers)
  =/  lines  (split '\0a' text)
  =/  fields=headers  ~
  |-
  ?~  lines  `(flop fields)
  =/  line  (trip i.lines)
  ?~  line  ~
  ?.  ?~(t.lines & =((rear line) 13))  ~
  =/  line  ?:(?=(~ t.lines) line (scag (dec (lent line)) ^-(tape line)))
  ?.  (levy line |=(ch=@tD &((gte ch 32) (lte ch 126))))  ~
  =/  pair  (split-first ':' (crip line))
  ?~  pair  ~
  =/  name  (lower p.u.pair)
  ?.  &((token name) !(lien fields |=([p=@t q=@t] =(p name))))  ~
  $(lines t.lines, fields [[name (trim q.u.pair)] fields])
++  extract
  |=  [fields=headers body=octs]
  ^-  (unit octs)
  ?.  (lte (met 3 q.body) p.body)  ~
  =/  delimiter  (boundary fields)
  ?~  delimiter  ~
  =/  first  (rap 3 ~['--' u.delimiter '\0d\0a'])
  ?.  &(=(first (cut 3 [0 (met 3 first)] q.body)) (lte (met 3 first) p.body))  ~
  =/  separator  (find '\0d\0a\0d\0a' body (met 3 first))
  ?~  separator  ~
  =/  head-width  (sub u.separator (met 3 first))
  =/  head  (cut 3 [(met 3 first) head-width] q.body)
  ?.  =((met 3 head) head-width)  ~
  =/  parsed  (part-headers `@t`head)
  ?~  parsed  ~
  =/  disposition  (one-header u.parsed 'content-disposition')
  ?~  disposition  ~
  =/  info  (parameters u.disposition)
  ?~  info  ~
  ?.  &(=(kind.u.info 'form-data') =((~(gut by params.u.info) 'name' '') 'data'))  ~
  =/  media  (one-header u.parsed 'content-type')
  ?.  ?~(media & =((lower (trim u.media)) 'application/octet-stream'))  ~
  =/  transfer  (one-header u.parsed 'content-transfer-encoding')
  ?.  ?~(transfer & =((lower (trim u.transfer)) 'binary'))  ~
  =/  start  (add u.separator 4)
  =/  middle  (find (rap 3 ~['\0d\0a--' u.delimiter '\0d\0a']) body start)
  ?^  middle  ~
  =/  ending  (rap 3 ~['\0d\0a--' u.delimiter '--'])
  =/  last=(unit @ud)
    =/  offset  start
    |-
    =/  candidate  (find ending body offset)
    ?~  candidate  ~
    =/  after  (add u.candidate (met 3 ending))
    ::  A marker prefix inside ciphertext is not a MIME delimiter line.
    ?:  |(=(after p.body) &((lte (add after 2) p.body) =('\0d\0a' (cut 3 [after 2] q.body))))
      candidate
    $(offset +(u.candidate))
  ?~  last  ~
  =/  after  (add u.last (met 3 ending))
  ?.  |(=(after p.body) =((add after 2) p.body))  ~
  ?:  !=(after p.body)
    ?.  =('\0d\0a' (cut 3 [after 2] q.body))  ~
    `[(sub u.last start) (cut 3 [start (sub u.last start)] q.body)]
  `[(sub u.last start) (cut 3 [start (sub u.last start)] q.body)]
--
