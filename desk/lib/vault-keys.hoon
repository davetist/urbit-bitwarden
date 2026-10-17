::  Normalize official-client key-management requests into account state.
::  Authentication hashes are checked for wire consistency only, never copied.
::  Authorization and atomic vault replacement belong to the Gall agent.
|%
+$  json
  $@  ~
  $%  [%a p=(list json)]
      [%b p=?]
      [%o p=(map @t json)]
      [%n p=@ta]
      [%s p=@t]
  ==
++  get
  |=  [obj=json key=@t]
  ^-  json
  ?.  ?=([%o *] obj)  ~
  (~(gut by p.obj) key ~)
++  has
  |=  [obj=json key=@t]
  ^-  ?
  ?.  ?=([%o *] obj)  |
  (~(has by p.obj) key)
++  put
  |=  [obj=json key=@t value=json]
  ^-  [%o p=(map @t json)]
  ?>  ?=([%o *] obj)
  [%o (~(put by p.obj) key value)]
++  text
  |=  value=json
  ^-  ?
  ?.  ?=([%s *] value)  |
  !=('' p.value)
++  natural
  |=  value=json
  ^-  (unit @ud)
  ?.  ?=([%n *] value)  ~
  (rush p.value dem)
++  positive
  |=  value=json
  ^-  ?
  =/  number  (natural value)
  ?~  number  |
  !=(0 u.number)
++  agrees
  |=  [obj=json key=@t value=json]
  ^-  ?
  |(!(has obj key) =((get obj key) value))
++  fallback
  |=  [obj=json key=@t default=json]
  ^-  json
  ?:  (has obj key)  (get obj key)
  default
++  kdf
  |=  [kind=json iterations=json memory=json parallelism=json]
  ^-  (unit json)
  ?.  (positive iterations)  ~
  ?:  =(kind n+'0')
    ?.  &(=(~ memory) =(~ parallelism))  ~
    `[%o (malt ~[['kdfType' kind] ['iterations' iterations] ['memory' ~] ['parallelism' ~]])]
  ?.  &(=(kind n+'1') (positive memory) (positive parallelism))  ~
  `[%o (malt ~[['kdfType' kind] ['iterations' iterations] ['memory' memory] ['parallelism' parallelism]])]
++  modern-kdf
  |=  data=json
  ^-  (unit json)
  ?.  ?=([%o *] data)  ~
  (kdf (get data 'kdfType') (get data 'iterations') (get data 'memory') (get data 'parallelism'))
++  current-kdf
  |=  account=json
  ^-  (unit json)
  (kdf (fallback account 'kdf' n+'0') (fallback account 'kdfIterations' n+'600000') (get account 'kdfMemory') (get account 'kdfParallelism'))
++  same-legacy-kdf
  |=  [data=json config=json]
  ^-  ?
  ?&  (agrees data 'kdf' (get config 'kdfType'))
      (agrees data 'kdfType' (get config 'kdfType'))
      (agrees data 'kdfIterations' (get config 'iterations'))
      (agrees data 'kdfMemory' (get config 'memory'))
      (agrees data 'kdfParallelism' (get config 'parallelism'))
  ==
++  install
  |=  [account=json config=json salt=json key=json hint-source=json]
  ^-  (unit json)
  ?.  &(?=([%o *] account) (text salt) (text key))  ~
  =/  hint  (get hint-source 'masterPasswordHint')
  ?.  |(=(~ hint) ?=([%s *] hint))  ~
  =.  account  (put account 'key' key)
  =.  account  (put account 'salt' salt)
  =.  account  (put account 'kdf' (get config 'kdfType'))
  =.  account  (put account 'kdfIterations' (get config 'iterations'))
  =.  account  (put account 'kdfMemory' (get config 'memory'))
  =.  account  (put account 'kdfParallelism' (get config 'parallelism'))
  =?  account  (has hint-source 'masterPasswordHint')
    (put account 'masterPasswordHint' hint)
  `account
++  normalize-change
  |=  [account=json data=json change-kdf=?]
  ^-  (unit json)
  ?.  &(?=([%o *] account) ?=([%o *] data))  ~
  ?.  (text (get data 'masterPasswordHash'))  ~
  =/  current  (current-kdf account)
  ?~  current  ~
  =/  salt  (fallback account 'salt' (get account 'email'))
  ?.  (agrees data 'salt' salt)  ~
  =/  auth  (get data 'authenticationData')
  =/  unlock  (get data 'unlockData')
  ?:  |((has data 'authenticationData') (has data 'unlockData'))
    ?.  &(?=([%o *] auth) ?=([%o *] unlock))  ~
    =/  auth-kdf  (modern-kdf (get auth 'kdf'))
    =/  unlock-kdf  (modern-kdf (get unlock 'kdf'))
    ?~  auth-kdf  ~
    ?~  unlock-kdf  ~
    ?.  =(u.auth-kdf u.unlock-kdf)  ~
    ?.  &(=((get auth 'salt') salt) =((get unlock 'salt') salt))  ~
    ?.  |(change-kdf =(u.auth-kdf u.current))  ~
    ?.  (same-legacy-kdf data u.auth-kdf)  ~
    =/  hash  (get auth 'masterPasswordAuthenticationHash')
    =/  key  (get unlock 'masterKeyWrappedUserKey')
    ?.  &((text hash) (text key) (agrees data 'newMasterPasswordHash' hash) (agrees data 'key' key))  ~
    (install account u.auth-kdf salt key data)
  ?.  &((text (get data 'newMasterPasswordHash')) (text (get data 'key')))  ~
  =/  config
    ?:  change-kdf
      (kdf (fallback data 'kdf' (get data 'kdfType')) (get data 'kdfIterations') (get data 'kdfMemory') (get data 'kdfParallelism'))
    current
  ?~  config  ~
  ?.  (same-legacy-kdf data u.config)  ~
  (install account u.config salt (get data 'key') data)
++  normalize-rotation
  |=  [account=json data=json]
  ^-  (unit json)
  ?.  &(?=([%o *] account) ?=([%o *] data))  ~
  ?.  (text (get data 'oldMasterKeyAuthenticationHash'))  ~
  =/  unlocks  (get data 'accountUnlockData')
  =/  master  (get unlocks 'masterPasswordUnlockData')
  =/  keys  (get data 'accountKeys')
  ?.  &(?=([%o *] master) ?=([%o *] keys))  ~
  =/  current  (current-kdf account)
  ?~  current  ~
  =/  config  (kdf (get master 'kdfType') (get master 'kdfIterations') (get master 'kdfMemory') (get master 'kdfParallelism'))
  ?~  config  ~
  ?.  &(=(u.config u.current) =((get master 'email') (get account 'email')))  ~
  =/  salt  (fallback account 'salt' (get account 'email'))
  ?.  =((get master 'email') salt)  ~
  ?.  (text (get master 'masterKeyAuthenticationHash'))  ~
  =/  updated  (install account u.config salt (get master 'masterKeyEncryptedUserKey') master)
  ?~  updated  ~
  =/  pair  (get keys 'publicKeyEncryptionKeyPair')
  =/  private  (get keys 'userKeyEncryptedAccountPrivateKey')
  =/  public  (get keys 'accountPublicKey')
  =/  signed=json  ~
  ?^  pair
    ?.  ?=([%o *] pair)  ~
    =/  modern-private  (get pair 'wrappedPrivateKey')
    =/  modern-public  (get pair 'publicKey')
    ?.  &((text modern-private) (text modern-public))  ~
    ?.  &(|(=(~ private) =(private modern-private)) |(=(~ public) =(public modern-public)))  ~
    =/  signed  (get pair 'signedPublicKey')
    ?.  |(=(~ signed) (text signed))  ~
    (finish-rotation u.updated keys modern-private modern-public signed)
  (finish-rotation u.updated keys private public signed)
++  finish-rotation
  |=  [account=json keys=json private=json public=json signed=json]
  ^-  (unit json)
  ?.  &((text private) (text public) =(public (get account 'publicKey')))  ~
  =/  signature  (get keys 'signatureKeyPair')
  =/  security  (get keys 'securityState')
  ::  V2 fields form a complete set. Never retain an old wrapped signing key
  ::  under a newly rotated user key, or silently downgrade a V2 account.
  =/  previous  (get account 'accountKeys')
  ?:  &(=(~ signature) |(!=(~ signed) !=(~ security) !=(~ (get previous 'signatureKeyPair'))))  ~
  =/  sanitized-signature=json  ~
  =/  sanitized-security=json  ~
  =^  sanitized-signature  sanitized-security
    ?~  signature  [~ ~]
    ?.  &(?=([%o *] signature) ?=([%o *] security) (text signed))  [~ ~]
    =/  wrapped  (get signature 'wrappedSigningKey')
    =/  verifying  (get signature 'verifyingKey')
    =/  algorithm  (get signature 'signatureAlgorithm')
    =/  state  (get security 'securityState')
    =/  version  (get security 'securityVersion')
    ?.  &((text wrapped) (text verifying) (text state) ?=(^ (natural version)))  [~ ~]
    ?.  |((text algorithm) ?=(^ (natural algorithm)))  [~ ~]
    :-  [%o (malt ~[['wrappedSigningKey' wrapped] ['verifyingKey' verifying] ['signatureAlgorithm' algorithm]])]
    [%o (malt ~[['securityState' state] ['securityVersion' version]])]
  ?:  &(!=(~ signature) =(~ sanitized-signature))  ~
  =/  normalized-pair=json
    [%o (malt ~[['wrappedPrivateKey' private] ['publicKey' public] ['signedPublicKey' signed]])]
  =/  normalized=json
    [%o (malt ^-((list [p=@t q=json]) ~[['publicKeyEncryptionKeyPair' normalized-pair] ['signatureKeyPair' sanitized-signature] ['securityState' sanitized-security]]))]
  =.  account  (put account 'privateKey' private)
  =.  account  (put account 'publicKey' public)
  =.  account  (put account 'accountKeys' normalized)
  ::  This ID describes the old user key; let the client backfill the new ID.
  =.  account  (put account 'userKeyId' ~)
  `account
--
