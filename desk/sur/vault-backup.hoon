::  Portable vault content only. No ship, sessions or Connect authority.
/+  va=vault-attachments
|%
+$  snapshot
  $:  %urbitwarden-backup  %1
      account=json  ciphers=(map @t json)  folders=(map @t json)
      attachments=store:va  serial=@ud  revision=@da
  ==
+$  request  [origin=@t data=snapshot]
--
