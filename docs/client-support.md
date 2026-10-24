# Official-client support

On 2026-10-24, the signed macOS desktop 2026.10.0 initially redirected **Change master password** to Urbitwarden's setup page, which has no such control. Its installed code selects the native dialog only when the server advertises `pm-32413-multi-client-password-management`. The development desk advertises that flag; after the desktop refreshed its cached server configuration, the native password change, new-password unlock, retained-item decryption and **File → Sync now** passed. Independent-client reauthentication with the post-change password was not observed.

The development test vault was subsequently recovered by restoring an older retained encrypted key wrapper while preserving its account ID and encrypted item. Signed macOS desktop 2026.10.1 and a separate fresh official CLI 2026.10.0 profile completed SSO and local unlock with the restored previous password; the desktop displayed the item and the CLI synced and decrypted it. Chromium refreshed the ship page's one-item summary. This proves fresh-client access after the recovery, not independent-client reauthentication with the post-change password. [Post-recovery observation](../evidence/current-2026-10-24/post-recovery-clients.json). The historical-wrapper risk is described in [known limitations](known-limitations.md#older-encrypted-key-wrappers).

Earlier releases reported the same fixed account ID from every installation. The official desktop stores account keys under that ID, so using multiple Urbitwarden servers in one desktop profile could mix cached keys and cause an invalid-master-password error. New enrollments now receive a generated account UUID. Existing accounts without one gain a UUID when the desk loads; their cached client sessions are revoked, so clients must sign in again through SSO and re-download the encrypted vault. The migration retains wrapped keys, vault items, folders and attachments. The development desk has migrated; already-published alpha desks have not been republished with this change.

The [current development policy](readiness-policy.md) supersedes old qualification gates. The [personal Vaultwarden parity scope](vaultwarden-parity.md) defines the requested target; the dated observations below describe exercised workflows, not prerequisites for daily use.

The Urbitwarden desk is an Urbit-native personal-vault backend. Connect owns generic authorization; the Urbitwarden desk owns encrypted vault storage and Bitwarden protocol behavior. Stock Vere/Gall/Eyre serve the backend. Official distribution clients are unmodified; the iOS Simulator build uses unchanged official release source.

## Release-candidate checks — 2026-10-24

Official CLI 2026.10.0 uploaded an encrypted attachment, downloaded and decrypted it, exported selected items as JSON, and reimported them on the development moon. [Client result](../evidence/current-2026-10-24/cli-extended-workflows.json). A separate disposable-ship run installed the published-alpha source, then updated the running desk in place: the encrypted item kept its ID and decrypted after a fresh Connect approval and CLI SSO. The account-ID migration intentionally revoked the old session and grant, so an alpha user must sign in again. [Upgrade result](../evidence/current-2026-10-24/upgrade-candidate.json).

An encrypted portable vault snapshot restored to a different disposable ship; fresh CLI SSO/unlock decrypted the password, and a browser WebAuthn challenge verified against the recovered passkey's original public key. This used a virtual authenticator and CLI import. [Recovery result](../evidence/current-2026-10-24/recovery-candidate.json). A separate owned test ship exercised website-passkey creation and use through the unmodified official Chrome extension 2026.10.0, then used the same passkey after the ship and browser restarted. [Extension passkey result](../evidence/passkey/result.json). Another synthetic ship tested an API-initiated password rewrap: an older official CLI profile became unauthenticated, while fresh official CLI SSO and local unlock with the new password decrypted the retained item. [Cross-client result](../evidence/password-reauth/result.json). A fresh synthetic ship tested an API-initiated PBKDF2 iteration change from 600,000 to 650,000: an older CLI profile became unauthenticated, and a fresh official CLI profile adopted the new KDF setting and decrypted the retained item. [KDF compatibility result](../evidence/kdf-reauth/result.json). A focused [desk security review](../evidence/current-2026-10-24/security-review.md) covered the candidate source without a live attack replay. Desktop password change, new-password unlock, item decryption and sync were observed as described above. The synthetic checks do not establish independent-client reauthentication after that particular desktop action. [Bitwarden documents KDF changes in its web app](https://bitwarden.com/help/kdf-algorithms/); Urbitwarden 0.2.0 has no Bitwarden web vault, so changing KDF settings is deferred from stable user-facing support. The synthetic result establishes API/client compatibility only.

## Current client check — 2026-10-21

Connect and Urbitwarden were installed together on an owned, networked development moon with trusted HTTPS served by stock Eyre. Fresh owner enrollment and the following actual client workflows passed. [Source and observation record](../evidence/current-2026-10-21/client-workflows.json).

| Client | Observed workflows |
|---|---|
| Official CLI 2026.10.0 | Fresh SSO and local unlock; login creation; independent decryption of extension, iOS and desktop edits; trash/restore; lock/re-unlock; sync rejected after Connect session revocation; fresh SSO reconnect; sync/decryption after the moon restarted |
| Official Chrome extension 2026.10.0 in Chromium | Fresh SSO and local unlock; automatic initial sync; login password/notes editing; changes independently decrypted by CLI |
| Signed official macOS desktop 2026.10.0 | SSO through the native OS callback; local unlock; automatic initial sync; notes editing; changes independently decrypted by CLI |
| Unchanged official iOS 2026.10.0 release source in Simulator | Fresh system-browser SSO and native callback; consent at default scale; local unlock; initial sync; notes editing; independent CLI decryption; app restart/local re-unlock and readback of the desktop edit |

Desktop consent was completed in isolated Chromium; its default-browser owner-login path was not qualified. The extension used the official release ZIP, loaded unpacked without changes. The iOS result is an official-source Simulator build, not App Store or physical-device acceptance. Android and Windows/Linux desktop were not exercised. This run did not recheck website autofill, passkeys, attachments or import/export; earlier observations below remain dated evidence for their own source versions.

The moon restarted and existing clients decrypted the retained item. This checks persistence across restart; the later portable vault recovery is documented above. Immediate push remains unsupported; use **Sync now** for immediate cross-client refresh. Start with the short [tester guide](tester-guide.md).

## Historical versions and evidence boundary

The subsequent [personal-vault implementation](personal-vault-api.md) changes these sources. Its new bulk/archive, attachment, domain and account-management contracts have not been exercised in the historical runs below.

The **2026-10-16 rerun** exercised both then-current standalone desks together on a fresh owned fake ship. It includes the JWT/session-identifier repairs and the repository split. [Readiness assessment](../evidence/current-2026-10-16/assessment.md), [actual results](../evidence/current-2026-10-16/results.json), and [tested source hashes](../evidence/current-2026-10-16/source-pair.json) replace the older run as the evidence for these workflows. Commit fields identify starting HEADs; file hashes identify the tested working trees. They are provenance, not compatibility pins.

| Client | Historically observed checks | Evidence |
|---|---|---|
| Official CLI 2026.9.1 | Fresh SSO/local unlock; all four personal types; folder create/rename/delete; JSON export → delete → import with folder relationships; trash/restore; lock/re-unlock; sync denied after owner revocation | [CLI results](../evidence/current-2026-10-16/official-cli-usability.json), [lifecycle](../evidence/current-2026-10-16/official-cli-lifecycle.json), [revocation](../evidence/current-2026-10-16/native-revocation.json) |
| Official Chrome extension 2026.9.3 | Fresh SSO/local unlock; automatic initial sync; explicit cross-client Sync now; controlled-page toolbar autofill before/after password editing; independent CLI decryption | [Autofill](../evidence/current-2026-10-16/current-extension-autofill.json), [CLI readback](../evidence/current-2026-10-16/current-extension-cli-readback.json) |
| Signed official macOS desktop 2026.9.1 | Fresh SSO through normal OS callback; local unlock; automatic initial sync; note create/edit/view; independent CLI decryption | [Launch conditions](../evidence/current-2026-10-16/current-desktop-launch.json), [CLI readback](../evidence/current-2026-10-16/current-desktop-cli-readback.json) |
| Unchanged official iOS 2026.9.1 source, build 3533, in Simulator | Fresh SSO/callback/local unlock; initial sync; note creation and title/body edit; cross-client Sync now; restart/local re-unlock; independent CLI decryption | [Results and qualifications](../evidence/current-2026-10-16/results.json), [CLI readback](../evidence/current-2026-10-16/current-ios-cli-readback.json) |

The initial CLI SSO failure is corrected by the owner-authorized initial-token lifetime exception. The [current correction record](../evidence/cli-signin-fix-2026-10-16/assessment.md) reports 16/16 new-profile first attempts, real expiry/revocation and official CLI vault workflows. The separate iOS consent correction verifies approval at default page scale in the actual system browser. Untested behavior remains labelled as unobserved; it is not a mandatory readiness gate.

Android **2026.9.1-bwpm** has implemented source-contract support, not installed-client acceptance. Physical iOS/Android devices, the signed App Store iOS distribution and Windows/Linux desktop have not been exercised here. Periodic automatic-sync timing is source-confirmed, not measured by these runs. Prior CLI/extension trash/restore and native restart evidence remains in [the hardening report](../evidence/remaining-native-hardening.md).

The owner UI completed legacy extension migration and enabled all four client registrations. Native API/folder-import checks and three generic callback tests passed, including large imports, folder mapping, atomic failure behavior and folder deletion without item loss. The required iOS `/api/config` server URL field was corrected with a failing-then-passing regression check. [Native API evidence](../evidence/review-fixes/usability-api.json), [folder/import evidence](../evidence/review-fixes/folders-import-functional.json).

Manifest-verified native deployment and full stopped-pier recovery passed on the owned fake ship. The restored runtime booted and official CLI locally unlocked/synchronized/decrypted a known item; the original stopped copy was preserved and never ran concurrently. This does not qualify networked real-ship migration or public certificate renewal. [Deployment evidence](../evidence/review-fixes/native-packaged-deploy.json), [recovery evidence](../evidence/review-fixes/native-recovery-functional.json).

| Action in the historical run | Implementation at that time and observed evidence | Historical validation boundary |
|---|---|---|
| Enrollment and connection setup | Owner UI completed legacy extension migration and enabled CLI, extension, desktop and mobile registrations | Fresh-account UI behavior is separate from each installed client’s SSO acceptance |
| Enterprise SSO and local unlock | Passed in CLI, extension, signed macOS desktop and official-source iOS Simulator | Android/physical devices/other desktop OS not exercised; no new transmission audit |
| Personal item create/edit/sync | Four types passed in CLI; extension password edit/autofill, desktop note edit, and iOS note creation/title/body edit passed with CLI readback | UI acceptance is limited to those demonstrated item actions |
| Folders and personal import | Native API checks and official CLI folder/import round-trip passed, including preserved item associations | Other installed clients still need acceptance |
| Trash/restore | Native lifecycle/capacity tests, official CLI and extension previously exercised | Automatic purge was not implemented in that run |
| Lock and local re-unlock | Official CLI passed; iOS Simulator restart/local re-unlock passed | Other app restart/unlock combinations not separately exercised |
| Automatic refresh | Initial automatic sync demonstrated in extension, macOS desktop and iOS Simulator; explicit cross-client sync also passed | Long-interval fallback timing remains source-only; immediate push unsupported |
| Personal export | Official CLI local JSON export → delete → import recovered all four personal types and folder relationships | Password-protected JSON remains source-confirmed, not runtime-observed |
| Native installation and account recovery | Manifested two-desk deployment and full stopped-pier restore passed; restored native runtime and official CLI unlock/sync/decrypt passed | Owned fake-ship rehearsal; no networked real-ship migration or public certificate renewal claimed |
| Ordinary password sign-in | Server rejects prelogin with `sso_required`; prior CLI rejection evidence retained | Fresh pre-transmission verification deferred |
| Master-password re-prompt | Action-specific behavior; export's upstream default confirms the password locally | Other prompts and expanded transmission checks remain outside this qualification |
| Password change, account deletion, account recovery service | Unsupported in that source version | Restoring an intact backup is separate from recovering a forgotten password |
| API keys, organizations, attachments, Sends, passkeys, immediate push | Outside that source version | No client-compatibility claim |

The stock client may display a 30-day bin-expiry message. Current source supports explicit restore/permanent deletion and optional operator-configured automatic expiry, disabled by default. See the [current implementation](personal-vault-api.md).

## Server URL and native clients

Connect registrations are created on the first valid SSO attempt for each client, after ship-owner authentication. The adapter translates the official wire IDs in the table below to `urbitwarden-cli`, `urbitwarden-browser`, `urbitwarden-desktop` and `urbitwarden-mobile`. Enrollment and ordinary page loads do not create registrations. Callback validation and consent remain specific to each client. A disabled registration is not automatically re-enabled.

Matching legacy registrations are renamed on use through Connect’s owner-authorized rename endpoint, preserving sessions and namespaces. A mismatched old callback policy requires review in Connect. Historical evidence below may describe the former bulk registration UI; it does not establish validation of this new flow.

Enter `https://your-ship/apps/urbitwarden` as the self-hosted server URL. Its API is `/apps/urbitwarden/api`, identity service `/apps/urbitwarden/identity`, and setup/SSO page `/apps/urbitwarden`. Connect consent remains at the ship origin's `/connect` routes. The desk leaves the origin root and unrelated applications available. See [installation and HTTPS renewal](install.md) and [backup/recovery](backup.md).

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

The desk therefore supports the clients' normal refresh endpoints and preserves their existing automatic behavior, while immediate push remains unsupported. The initial CLI exception and remaining session policy are described below.

## Retained authorization tokens — no password decryption

The owner accepts retention of authorization tokens in journal history as a known limitation, not a usability blocker. **These tokens cannot decrypt the vault or read passwords.** They authorize operations on encrypted data: a still-valid token may permit downloading, modifying or deleting ciphertext. They are not the master password or unwrapped vault key. Access tokens last **60 seconds**, except the initial CLI SSO token lasts **six minutes** to avoid its immediate-refresh startup race. The **30-day absolute Connect grant and five-second retry grace** remain unchanged. See [the recorded decision and native retention tools](known-limitations.md).

Native Behn timers remove expired cached token responses from active application state; reload prunes expired/orphaned entries and re-arms valid timers. Five-second retry responses remain durable for quick restarts. Cleanup does not erase older journal events or snapshots. A stalled/stopped runtime cannot process a timer, and request handling still checks expiry before returning a cached response.

Expanded client-action transmission checks and journal/security validation are deferred by request. Source compatibility and functional acceptance do not establish a new pre-transmission guarantee for unsupported actions. The previously identified token-derivation repairs are present in the tested sources. Native cache/migration tests passed, but these functional workflows do not constitute expanded journal or adversarial validation.

## Historical verification commands

These commands are retained as historical reference and are not authorization to run tests under the current no-synthetic/no-soak direction. Use the owned review fixture and its matching enrollment/client profiles. Do not run parallel CLI processes against one profile. These are functional/correctness commands, not a record that every command has passed the current changes:

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

The browser's functional-only mode disables request/key capture. Existing mixed authorization/replay suites and journal audit remain available as historical tooling, but are outside this execution and must not be reported as newly passing. Password-protected export, Android installed-client behavior, physical devices and other desktop operating systems have not been exercised here. Historical native deployment/recovery, official-client workflows and CLI JSON export/import results are linked above. No CORS workaround or desktop sandbox change was needed for the tested default signed macOS client.
