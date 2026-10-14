::  Kernel-derived response routing; verified against pinned Gall/Eyre 408.
::  Eyre HTTP and direct Gall subscribers can share src/sap. Only the actual
::  /eyre/watch-response duct may receive an HTTP response fact.
|%
++  http-watch
  |=  [incoming=bitt:gall source=@p route=path]
  ^-  ?
  ?.  ?=([%http-response @ ~] route)  |
  =/  wanted=path  [%eyre %watch-response i.t.route ~]
  =/  matches
    %+  skim  ~(tap by incoming)
    |=  [d=(list path) s=@p p=path]
    =(p route)
  =/  seen=?  |
  |-  ^-  ?
  ?~  matches  seen
  =/  [d=(list path) s=@p p=path]  i.matches
  ?~  d  |
  ?.  &(=(s source) =(i.d wanted))  |
  $(matches t.matches, seen &)
--
