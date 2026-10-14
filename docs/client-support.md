# Official-client support

The Bitwarden desk is an Urbit-native personal-vault backend. Connect owns generic authorization; the Bitwarden desk owns encrypted vault storage and Bitwarden protocol behavior. Stock Vere/Gall/Eyre serve the backend. Official distribution clients are unmodified; the iOS Simulator build uses unchanged official release source.

## Versions and evidence boundary

The retained usability run from before the repository split exercised the following clients against `/apps/bitwarden`. These results retain their original scope and are not a new run against every later Connect version. Bitwarden targets the latest Connect desk; see [repository provenance](repository-split.md).

| Client | Completed functional checks | Evidence |
|---|---|---|
| Official CLI 2026.9.1 | Fresh SSO/local unlock; encrypt/sync/decrypt login, note, card and identity; folder create/rename/delete; JSON export → delete → import recovery with folder relationships | [CLI results](../evidence/review-fixes/official-cli-usability.json) |
| Official Chrome extension 2026.9.3 | Fresh SSO/local unlock; automatic initial sync; explicit Sync now; controlled-page autofill before and after password editing; edited item read back by CLI | [Extension results](../evidence/review-fixes/official-extension-usability.json), [CLI readback](../evidence/review-fixes/extension-edit-readback.json) |
| Signed official macOS desktop 2026.9.1 | Normal OS SSO callback; local unlock; automatic initial sync; secure-note create/edit/view; independent CLI readback | [Desktop results](../evidence/review-fixes/official-desktop-usability.json) |
| Unchanged official iOS 2026.9.1 source, build 3533, in Simulator | SSO/callback/local unlock; automatic initial sync; existing-item view; secure-note creation/title editing; explicit sync of another client's item; app restart/local re-unlock; CLI readback | [iOS results](../evidence/review-fixes/ios-functional-progress.json), [CLI readback](../evidence/review-fixes/ios-cli-readback.json) |

Android **2026.9.1-bwpm** has implemented source-contract support, not installed-client acceptance. Physical iOS/Android devices, the signed App Store iOS distribution and Windows/Linux desktop remain unqualified. Periodic automatic-sync timing is source-confirmed, not measured by these runs. Prior CLI/extension trash/restore and native restart evidence remains in [the hardening report](../evidence/remaining-native-hardening.md).

The owner UI completed legacy extension migration and enabled all four client registrations. Native API/folder-import checks and three generic callback tests passed, including large imports, folder mapping, atomic failure behavior and folder deletion without item loss. The required iOS `/api/config` server URL field was corrected with a failing-then-passing regression check. [Native API evidence](../evidence/review-fixes/usability-api.json), [folder/import evidence](../evidence/review-fixes/folders-import-functional.json).

Manifest-verified native deployment and full stopped-pier recovery passed on the owned fake ship. The restored runtime booted and official CLI locally unlocked/synchronized/decrypted a known item; the original stopped copy was preserved and never ran concurrently. This does not qualify networked real-ship migration or public certificate renewal. [Deployment evidence](../evidence/review-fixes/native-packaged-deploy.json), [recovery evidence](../evidence/review-fixes/native-recovery-functional.json).

| Action | Implementation and current evidence | Validation boundary |
|---|---|---|
| Enrollment and connection setup | Owner UI completed legacy extension migration and enabled CLI, extension, desktop and mobile registrations | Fresh-account UI behavior is separate from each installed client’s SSO acceptance |
| Enterprise SSO and local unlock | Passed in CLI, extension, signed macOS desktop and official-source iOS Simulator | Android/physical devices/other desktop OS unqualified; no new transmission audit |
| Personal item create/edit/sync | Four types passed in CLI; extension password edit/autofill, desktop note edit, and iOS note creation/title edit passed with CLI readback | UI acceptance is limited to those demonstrated item actions |
| Folders and personal import | Native API checks and official CLI folder/import round-trip passed, including preserved item associations | Other installed clients still need acceptance |
| Trash/restore | Native lifecycle/capacity tests, official CLI and extension previously exercised | Automatic 30-day trash purge is not implemented |
| Lock and local re-unlock | Official CLI passed; iOS Simulator restart/local re-unlock passed | Other app restart/unlock combinations not separately qualified |
| Automatic refresh | Initial automatic sync demonstrated in extension, macOS desktop and iOS Simulator; explicit cross-client sync also passed | Long-interval fallback timing remains source-only; immediate push unsupported |
| Personal export | Official CLI local JSON export → delete → import recovered all four personal types and folder relationships | Password-protected JSON remains source-confirmed, not runtime-qualified |
| Native installation and account recovery | Manifested two-desk deployment and full stopped-pier restore passed; restored native runtime and official CLI unlock/sync/decrypt passed | Owned fake-ship rehearsal; no networked real-ship migration or public certificate renewal claimed |
| Ordinary password sign-in | Server rejects prelogin with `sso_required`; prior CLI rejection evidence retained | Fresh pre-transmission verification deferred |
| Master-password re-prompt | Action-specific behavior; export's upstream default confirms the password locally | Other prompts and expanded transmission checks remain outside this qualification |
| Password change, account deletion, account recovery service | Unsupported by the desk | Restoring an intact backup is separate from recovering a forgotten password |
| API keys, organizations, attachments, Sends, passkeys, immediate push | Outside this personal-vault version | No client-compatibility claim |

The stock client may display a 30-day bin-expiry message. This desk supports explicit restore and permanent deletion, not automatic expiry.

## Server URL and native clients

Enter `https://your-ship/apps/bitwarden` as the self-hosted server URL. Its API is `/apps/bitwarden/api`, identity service `/apps/bitwarden/identity`, and setup/SSO page `/apps/bitwarden`. Connect consent remains at the ship origin's `/connect` routes. The desk leaves the origin root and unrelated applications available. See [installation and HTTPS renewal](install.md) and [backup/recovery](backup.md).

The client derives its service URLs from its configured base URL. Returning `environment.vault` in `/api/config` does not replace the desktop/extension/CLI's configured web-vault URL. An explicit advanced URL takes precedence over the base URL. [Official URL resolution](https://github.com/bitwarden/clients/blob/desktop-v2026.9.1/libs/common/src/platform/services/default-environment.service.ts#L405-L410), [precedence](https://github.com/bitwarden/clients/blob/desktop-v2026.9.1/libs/common/src/platform/services/default-environment.service.ts#L469-L490).

| Surface | Client ID | Callback contract | Initial SSO entry |
|---|---|---|---|
| CLI | `cli` | `http://localhost:8065` through `:8070` | Web page `/#/sso` beneath the configured base |
| Extension | `browser` | Configured base plus `/sso-connector.html` | Same web SSO entry |
| Desktop | `desktop` | `bitwarden://sso-callback`, plus exact localhost ports 8065–8070 for the official fallback | Same web SSO entry |
| iOS / Android | `mobile` | `bitwarden://sso-callback` for self-hosting | Identity `/connect/authorize` directly |

Mobile clients send their generated state unchanged. Both include `deeplinkScheme=bitwarden` in the code exchange; Android additionally sends the account email as `username`. Accepting that metadata does not enable a password grant. Wrapped-key responses retain the official shapes, and profile responses include a stable `creationDate` required by Android. [Desktop URL/callback](https://github.com/bitwarden/clients/blob/desktop-v2026.9.1/libs/auth/src/common/services/sso-redirect/sso-url.service.ts), [desktop fallback](https://github.com/bitwarden/clients/blob/desktop-v2026.9.1/apps/desktop/src/auth/services/sso-localhost-callback.service.ts), [Android SSO](https://github.com/bitwarden/android/blob/v2026.9.1-bwpm/app/src/main/kotlin/com/x8bit/bitwarden/data/auth/repository/util/SsoUtils.kt), [Android form](https://github.com/bitwarden/android/blob/v2026.9.1-bwpm/network/src/main/kotlin/com/bitwarden/network/api/UnauthenticatedIdentityApi.kt#L27-L48), [iOS SSO](https://github.com/bitwarden/ios/blob/v2026.9.1-bwpm/BitwardenShared/Core/Auth/Services/AuthService.swift#L474-L517), [iOS form](https://github.com/bitwarden/ios/blob/v2026.9.1-bwpm/BitwardenShared/Core/Auth/Models/Request/IdentityTokenRequestModel.swift#L50-L71).

## Folders, import and export

Folder names remain encrypted by the client. Folder create/update returns `id`, encrypted `name`, `revisionDate` and the `folder` object marker. Deleting folders clears item associations without deleting the items. Personal import accepts encrypted ciphers, folders and cipher-index/folder-index relationships in one request. Existing destination folder IDs are reused; unknown imported folder IDs receive new server-owned IDs. The complete import is committed only after validation. [Official folder API](https://github.com/bitwarden/clients/blob/desktop-v2026.9.1/libs/common/src/vault/services/folder/folder-api.service.ts), [import request](https://github.com/bitwarden/clients/blob/desktop-v2026.9.1/libs/common/src/models/request/import-ciphers.request.ts), [import endpoint](https://github.com/bitwarden/clients/blob/desktop-v2026.9.1/libs/importer/src/services/import-api.service.ts).

Personal exports are generated in the official client. Password-protected JSON uses a separate export password and client-side encryption; it does not require the backend to verify or receive the vault password. The desktop/extension default confirmation verifies a master password locally. This source contract is not a newly completed request/journal assurance check. [CLI export](https://github.com/bitwarden/clients/blob/cli-v2026.9.1/apps/cli/src/tools/export.command.ts#L66-L93), [password-protected export](https://github.com/bitwarden/clients/blob/desktop-v2026.9.1/libs/tools/export-vault-core/src/services/individual-vault-export.service.ts#L69-L88), [confirmation contract](https://github.com/bitwarden/clients/blob/desktop-v2026.9.1/libs/auth/src/angular/user-verification/user-verification-dialog.types.ts#L66-L86).

## Automatic sync and immediate updates

The native backend exposes account revision and sync endpoints and advances revision on vault mutations. Official clients upload their own changes and can refresh automatically; explicit **Sync now** is also available. Automatic refresh must not be confused with immediate server-pushed updates.

| Pinned client | Source-confirmed automatic fallback/lifecycle behavior |
|---|---|
| Extension 2026.9.3 | A five-minute scheduler checks whether six hours have elapsed since the last sync before running fallback sync. This is **not five-minute vault synchronization**. |
| Desktop 2026.9.1 | Fallback sync is gated on six hours since the last sync; account/unlock flows can also trigger sync. |
| Android 2026.9.1-bwpm | Login/vault-view initialization invokes `syncIfNecessary`, normally requiring 30 minutes since the last sync. This is a lifecycle check, not a guaranteed background timer. |
| iOS 2026.9.1-bwpm | Vault-list appearance invokes sync with a 30-minute minimum interval. It is not a guarantee that a suspended app will refresh every 30 minutes. |

Initial automatic sync after login/local unlock was demonstrated in the extension, macOS desktop and iOS Simulator. The longer periodic/lifecycle timings in this table come from pinned upstream source, not elapsed-time acceptance tests. [Extension scheduler](https://github.com/bitwarden/clients/blob/browser-v2026.9.3/libs/platform/src/background-sync/background-sync.service.ts), [extension six-hour guard](https://github.com/bitwarden/clients/blob/browser-v2026.9.3/apps/browser/src/background/main.background.ts#L2231-L2242), [desktop guard](https://github.com/bitwarden/clients/blob/desktop-v2026.9.1/apps/desktop/src/app/app.component.ts#L384-L398), [Android check](https://github.com/bitwarden/android/blob/v2026.9.1-bwpm/app/src/main/kotlin/com/x8bit/bitwarden/data/vault/manager/VaultSyncManagerImpl.kt#L244-L255), [iOS appearance trigger](https://github.com/bitwarden/ios/blob/v2026.9.1-bwpm/BitwardenShared/UI/Vault/Vault/VaultList/VaultListProcessor.swift#L250-L264), [iOS interval](https://github.com/bitwarden/ios/blob/v2026.9.1-bwpm/BitwardenShared/Core/Platform/Utilities/Constants.swift#L75-L76).

Immediate push cannot be supplied to these clients just by adding native HTTP long polling or SSE. The official desktop/extension SignalR implementation forces WebSockets and skips negotiation, so it never selects those HTTP fallbacks. Stock Vere 4.6's HTTP response interface does not expose a duplex WebSocket upgrade: status `101` is handled as a completed bodyless response. Mobile immediate updates use APNs/FCM; extension Web Push likewise uses a browser-provider delivery service. Those push services are outside the no-external-services scope. [Forced WebSocket transport](https://github.com/bitwarden/clients/blob/desktop-v2026.9.1/libs/common/src/platform/server-notifications/internal/signalr-connection.service.ts#L81-L104), [Vere response handling](https://github.com/urbit/vere/blob/vere-v4.6/pkg/vere/io/http.c#L1370-L1436), [Android Firebase receiver](https://github.com/bitwarden/android/blob/v2026.9.1-bwpm/app/src/standard/kotlin/com/x8bit/bitwarden/data/push/BitwardenFirebaseMessagingService.kt), [iOS APNs receiver](https://github.com/bitwarden/ios/blob/v2026.9.1-bwpm/Bitwarden/Application/AppDelegate.swift#L51-L66).

The desk therefore supports the clients' normal refresh endpoints and preserves their existing automatic behavior, while immediate push remains unsupported. Session lifetimes are unchanged.

## Retained authorization tokens — no password decryption

The owner accepts retention of authorization tokens in journal history as a known limitation, not a usability blocker. **These tokens cannot decrypt the vault or read passwords.** They authorize operations on encrypted data: a still-valid token may permit downloading, modifying or deleting ciphertext. They are not the master password or unwrapped vault key. Keep the existing **60-second access lifetime, 30-day absolute Connect grant and five-second retry grace**. See [the recorded decision and native retention tools](known-limitations.md).

Native Behn timers remove expired cached token responses from active application state; reload prunes expired/orphaned entries and re-arms valid timers. Five-second retry responses remain durable for quick restarts. Cleanup does not erase older journal events or snapshots. A stalled/stopped runtime cannot process a timer, and request handling still checks expiry before returning a cached response.

Expanded client-action transmission checks and journal/security validation are deferred by request. Source compatibility and functional acceptance do not establish a new pre-transmission guarantee for unsupported actions. The two previously identified token-derivation repairs remain assigned to separate work and unchanged by this usability work.

## Verification commands

Use the owned review fixture and its matching enrollment/client profiles. Do not run parallel CLI processes against one profile. These are functional/correctness commands, not a record that every command has passed the current changes:

```sh
CONNECT_BW_FIXTURE=review-fixes python3 scripts/test_fixture.py
CONNECT_BW_FIXTURE=review-fixes python3 scripts/test_start_ports.py
CONNECT_BW_FIXTURE=review-fixes python3 scripts/test_token_cache.py
CONNECT_BW_FIXTURE=review-fixes python3 scripts/test_refresh_compat.py
CONNECT_BW_FIXTURE=review-fixes python3 scripts/test_functional_lifecycle.py
CONNECT_BW_FIXTURE=review-fixes python3 scripts/test_soft_delete_bound.py
CONNECT_BW_FIXTURE=review-fixes python3 scripts/test_official_lifecycle.py
CONNECT_BW_FIXTURE=review-fixes python3 scripts/test_usability.py
CONNECT_BW_FIXTURE=review-fixes python3 scripts/test_folder_import.py
CONNECT_BW_FIXTURE=review-fixes python3 scripts/test_official_usability.py
CONNECT_BW_FIXTURE=review-fixes node scripts/browser.mjs --functional-only
```

The browser's functional-only mode disables request/key capture. Existing mixed authorization/replay suites and journal audit remain available as historical tooling, but are outside this execution and must not be reported as newly passing. Password-protected export, Android installed-client behavior, physical devices and other desktop operating systems remain unqualified. Current native deployment/recovery, official-client workflows and CLI JSON export/import results are linked above. No CORS workaround or desktop sandbox change was needed for the tested default signed macOS client.
