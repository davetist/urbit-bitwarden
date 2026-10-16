# Personal-vault feature parity with Vaultwarden

Research snapshot: 2026-10-16, upstream [`dani-garcia/vaultwarden` commit `58a980f850464f7d9cdc99a765df36f0a3308b91`](https://github.com/dani-garcia/vaultwarden/tree/58a980f850464f7d9cdc99a765df36f0a3308b91). This is a comparison with that source snapshot, not a claim that every upstream-main feature is exposed by every official client release. No Vaultwarden implementation code is copied into these native Hoon desks.

## Agreed product boundary

- One personal vault; shared vaults, organizations, collections, roles/groups and cross-user sharing are deferred.
- Sends are deferred, including public/password-protected Send links.
- Official Bitwarden clients manage passwords and other vault contents. No full browser web vault is planned.
- The ship page provides a brief vault/account summary and instructions for connecting the official clients. Enrollment and Connect consent remain available. It should not display decrypted content or keys.
- Urbit Connect exclusively identifies and authorizes the user. Password login, personal API-key login, email/OTP login, additional MFA login paths, passkey login to this backend and emergency-access authentication bypasses are excluded.
- A **stored passkey for a website** is personal-vault content and belongs in the parity target. It is distinct from using a passkey to log in to this backend.
- Changing the **local vault-encryption password**, KDF settings or wrapped encryption keys belongs to vault management. It must preserve Connect-only authentication and must not introduce a server-side password verifier. Existing clients' verification payloads need a specific compatibility design before implementation; blindly copying Vaultwarden account-auth endpoints would violate the boundary.

## Feature map

| Personal feature | Vaultwarden source | Current Urbit desk and work remaining |
|---|---|---|
| Login, secure note, card and identity items | [`CipherData` and cipher routes](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs) | CRUD, import and sync exist; these four types have historical official-client observations. |
| SSH keys; bank account, driving licence and passport types present in upstream main | [Cipher type serialization](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/cipher.rs) | Opaque JSON can preserve fields, but type/capability compatibility and official-client workflows are not established. Treat as implementation/compatibility work, not completed parity. |
| Custom fields, favourites, notes, URI matching, password history and re-prompt | [Cipher payload and partial-update routes](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs) | Full item writes retain opaque fields. Partial-update routes and client behavior still need implementation where absent. Local re-prompt must not become backend authentication. |
| Website passkeys and TOTP secrets/code generation | Cipher login data and client capabilities; [profile premium capability](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/user.rs) | Do not infer support from JSON retention. Current profile advertises `premium: false`; capability flags and complete official-client creation/use/edit workflows remain work. No paid-tier quota is intended. |
| Folders, nested-folder naming and moving items | [Folder API](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/folders.rs), cipher bulk-move routes | Folder CRUD, encrypted names and import relationships exist; deleting folders retains items. Bulk move and any missing client route variants remain work. |
| Bulk delete/restore/move; archive/unarchive; purge personal vault | [Cipher route list](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs) | Individual trash/restore/hard delete exist. Bulk cipher routes, archive/unarchive and explicit vault purge are missing. The current writer resets `archivedDate`, so archive parity is not present. |
| Trash retention | [Optional `trash_auto_delete_days`](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/config.rs) | Explicit trash/restore/permanent delete exist. Scheduled purge is missing. Upstream makes auto-delete optional; parity does not require imposing an arbitrary fixed 30-day deletion policy. |
| Encrypted attachments | [Attachment v2 upload/download/delete routes](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs) | Missing. Current cipher responses overwrite attachments with an empty array. Requires native encrypted-blob persistence and client-compatible transfer, cleanup and key-rotation handling. |
| Personal import/export and encrypted export formats | Cipher import plus official client tools | Encrypted personal import with folder mapping exists; plain JSON export/import was historically exercised. Password-protected export and additional formats are primarily client functions; preserve their API/data contracts without adding server password login. |
| Equivalent domains, autofill/save/update, icons | [Domain settings API](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/mod.rs) and icons implementation | Sync currently returns empty domain settings. Domain CRUD and icon compatibility remain work. Autofill/save/update UI belongs to clients; existing successful toolbar autofill does not establish every client action. |
| Vault-password change, KDF and encryption-key rotation | [Account key-management endpoints](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs) | Missing except the user-key-id setter. KDF data is fixed today. Add atomic wrapped-key/cipher updates and client refresh/invalidation behavior while retaining Connect authorization. |
| Delete/reset the personal vault and enrollment | Account deletion and personal purge endpoints | Missing. This means deliberate deletion of this application's data, not deletion of Urbit identity or bypassing Connect. It needs explicit user-facing destructive confirmation when implemented. |
| Password generation/search/local health reports | Official-client functions | Mostly client-side; server work is preserving compatible content and flags. Do not implement a second password-management UI on the ship. |
| Synchronization | Sync/revision APIs and notifications | Existing initial/manual sync and revision updates remain. Immediate server push is absent; adding it requires a transport/service decision, not a fake waiting-period gate. |

## External integrations

Breach-database lookup is excluded by the owner: no HIBP API key, breach-service account or outbound breach query is needed. Local client-side password-health functions remain in scope. Immediate push is a separate transport capability; it is not implemented, and no external push service or runtime dependency is enabled by this work. Normal sync/revision compatibility remains part of the personal-vault target.

## Delivery scope of this change

This change removes arbitrary quotas/readiness gates and records the agreed parity target. It does **not** implement all missing features in the table. Existing functionality and observed evidence remain labelled honestly. No synthetic fixtures, soak runs, tester quotas or long-duration readiness exercises are required or run. Verification of future behavior should address actual official-client workflows on the owner's intended setup when explicitly authorized.
