# Personal vault API implementation — 2026-10-17

This implementation extends the Urbitwarden desk. Connect remains the only backend authorization authority. The separate Connect desk needs no protocol change. No shared vaults, Sends, breach-database service, extra login mechanism or full browser vault is added.

State migrates `%0` and `%1` into `%2` by preserving their existing account, signing key, sessions, ciphers, folders, IDs, revisions, retry cache and CSRF data, then adding empty attachment storage and trash scheduling. The existing security migration still revokes `%0` sessions/cache/CSRF; `%1` sessions remain valid. Temporary download tickets are cleared on reload.

## Content and folders

The writer accepts the eight upstream cipher types (login, secure note, card, identity, SSH key, bank account, driving licence and passport), preserves encrypted type-specific fields, website passkeys, TOTP secrets, custom fields, URI matching, password history and local re-prompt metadata. Premium capability is enabled in profile and token responses so official clients can use their local TOTP/passkey/attachment functions without a paid-tier gate. Client releases still decide which types and controls they expose.

Full item writes validate personal ownership, type, folder references and supplied revision. Client-supplied attachment arrays cannot overwrite stored attachments. Archive metadata is preserved when omitted and honored when explicitly supplied. Clone requests do not acquire the source item's attachment blobs. Partial updates change only folder/favorite plus revision.

Bulk move, trash, restore, permanent delete and archive/unarchive validate the complete selected ID set before applying one state transition. Missing IDs fail without partial changes. Duplicate selected IDs are handled once. Folder deletion leaves items intact and clears their folder links. Personal import commits items/folders/relationships atomically; export encryption remains in official clients.

## Encrypted attachments

The v2 create route accepts encrypted file name, wrapped attachment key and exact encrypted byte length. It returns the official `attachment-fileUpload` response and relative upload URL. Upload accepts one multipart `data` part, including the official iOS charset-before-boundary header. Binary octet lengths preserve embedded and trailing zero bytes. A different overwrite or a declared-length mismatch is rejected; identical upload retry is accepted.

Upload completion preserves the prepare response's item revision because official iOS retains that response. First completion advances account sync revision. Deletion returns `{cipher: updatedCipher}`. Item hard deletion also removes its attachment data and download tickets.

An authenticated attachment metadata request issues a one-minute download URL bound to the existing Connect session, cipher and attachment. This matches [Vaultwarden’s file-download ticket lifetime](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L439-L443). Every byte download checks ticket expiry, current local session and live Connect grant. Reload clears tickets. These URLs authorize encrypted bytes only; the client decrypts them. Item edits can update attachment file-name/key wrappers without replacing the blob. No external object store is required. Logical removal does not erase historical Urbit events or backups.

## Settings and presentation

`GET`, `POST` and `PUT /api/settings/domains` support personal equivalent domains and exclusions from the standard global groups. The factual groups and stable IDs are sourced from the pinned Vaultwarden `global_domains.json`; the Hoon serialization/settings code is native. Sync omits excluded global groups. `POST`/`PUT /api/accounts/profile` update display name and culture.

The ship page shows only account setup, aggregate vault/folder/attachment counts and official-client connection instructions. It never renders decrypted contents. Counts come from authenticated bootstrap data; missing summary data is not replaced with fabricated zeroes.

`/icons/<domain>/icon.png` redirects to that website's HTTPS `/favicon.ico`, after hostname validation. The official client fetches the public icon directly; no ship-side fetch proxy or third-party icon service is introduced. This exposes the client's IP to that website and differs from Vaultwarden's cached icon proxy and HTML icon discovery. Websites without a usable root favicon use the client's fallback icon.

## Optional automatic trash expiry

Trash is retained indefinitely by default. The operator-only server preference is exposed through Connect-authorized `GET`/`POST`/`PUT /api/settings/vault`; it is not an extra login or an official-client settings screen. `trashAutoDeleteDays: null` disables expiry. A positive integer with `confirmAutoDelete: true` enables it and immediately removes already-expired trash. Subsequent cleanup runs daily. State stores the exact next wakeup so reload re-arms it and stale wakeups cannot create duplicate loops. This is the counterpart to Vaultwarden's optional server retention setting, not a fixed product quota. Ordinary client trash/restore/permanent-delete actions remain available regardless of this preference.

## Account encryption management

Owner decision, 2026-10-17: include these management operations with the disclosed official-client payloads. Password/KDF/key-rotation and some purge/account-delete requests contain password-derived authentication hashes, which can remain in Urbit request history. They are not plaintext passwords or unwrapped vault keys, but they are password-derived verifier material. The desk never stores or checks a password verifier in active vault state. Connect remains the only login and authorization mechanism; typing a password into an official client's management dialog does not add a backend password-authentication requirement.

`POST /api/accounts/password` and `/api/accounts/kdf` reconcile modern and legacy wrapped-key/KDF fields, reject contradictory values, and store only wrapped keys, salt, KDF metadata and hint. Token, unlock, sync and account-key responses use the same stored metadata. Supported KDFs are PBKDF2 and Argon2id, with positive algorithm parameters and no product-imposed upper quota.

`POST /api/accounts/key-management/rotate-user-account-keys` validates the complete current personal cipher/folder set, current item revisions, and exact attachment-key coverage before atomically committing re-encrypted content and account keys. Trash is included. Duplicate/unknown/missing records, stale revisions, inconsistent key aliases and unsupported nonempty organization/emergency/Sends data are rejected without partial replacement. Attachment bytes are preserved while their encrypted names/key wrappers change. Modern signed key/security-state metadata is retained as a complete compatible set; it is not silently downgraded. Successful user-key rotation clears the previous `userKeyId` so the official client can backfill the new key identity; password/KDF-only rewrapping retains it. The upstream folder-rotation request has no folder revision field, so a concurrent rename of an existing folder cannot be detected by that contract; avoid folder edits from another client while rotating keys.

Password/KDF/key changes rotate the security stamp, clear cached token responses, pending exchanges and temporary downloads, and revoke all other Bitwarden/Connect session families. The requesting session is retained so the official client can finish applying its local change. Existing absolute Connect grant expiry is not extended.

`POST /api/ciphers/purge` clears personal ciphers, folders, attachments and download tickets while retaining enrollment and account keys. `DELETE /api/accounts` and `POST /api/accounts/delete` clear this application's enrollment/data, cancel its cleanup timer, and revoke all sessions and pending exchanges. They do not delete Urbit identity or unrelated desks. These explicit destructive API calls rely on the official client's confirmation UI and a live Connect grant. They do not compare the compatibility password-hash field. `/api/accounts/verify-password` returns an explicit unsupported-verification error instead of falsely reporting password verification.

The inspected desktop and extension versions expose plain password changes, while optional user-key rotation is web-vault-only; the CLI declares rotation unsupported. Official CLI 2026.9.1 also has no personal-vault purge command ([command registration](https://github.com/bitwarden/clients/blob/cli-v2026.9.1/apps/cli/src/vault.program.ts)). The inspected iOS account-deletion flow locally derives its hash and directly sends `DELETE /accounts`, without a separate server password-verification call ([repository](https://github.com/bitwarden/ios/blob/6b5abc1e7d96f49f50a74ffac6ad93061475bc3e/BitwardenShared/Core/Auth/Repositories/AuthRepository.swift#L743-L755)). These are client UI boundaries. The server implements the contracts, but an unmodified installed client cannot expose a control it does not contain. No full web vault is added.

## Verification boundary

Source-contract review uses Vaultwarden `58a980f850464f7d9cdc99a765df36f0a3308b91`, official desktop/extension release sources and iOS `6b5abc1e7d96f49f50a74ffac6ad93061475bc3e`. The complete production Gall agent and its real imports compile against the declared Zuse 408 using stock Vere 4.6; the standalone attachment and key-normalization helpers also compiled. Source review, syntax checks, static asset inspection and deterministic source packaging are recorded in the [build evidence](../evidence/personal-vault-2026-10-17/README.md). No synthetic, unit, integration, fixture or soak tests have run. No deployment or current official-client workflow is claimed by this document.
