# Native SSO integration evidence

Fixture: fresh, isolated fake `~zod` under `.work/bitwarden-sso`, native Eyre HTTPS on localhost:19681. No original prototype fixture or real ship was changed. Backend: unmodified pinned Vere 4.6/kernel 408, Hoon/Gall/Eyre only. This report concerns the synthetic SSO workflow, not production readiness or alpha release qualification.

## Demonstrated official-client workflow

The official CLI 2026.9.1 and Chrome extension 2026.9.3 were verified byte-for-byte against their pinned upstream ZIP archives (1 CLI file, 191 extension files). See [artifact verification](official-clients-unmodified.json) and [download pins](../artifacts.json). Chrome for Testing 151.0.7922.34 ran the unpacked official extension in a dedicated profile with Developer mode enabled. The only TLS exception was the exact fixture certificate SPKI; CLI trust used its private CA file.

Browser-only enrollment created wrapped user/private-key envelopes. The actual CLI opened its SSO flow, received owner consent through Connect, validated its real loopback callback, and exited successfully. The actual extension completed its SSO connector flow and reached local unlock. Both decrypted the same vault. CLI created **Connect SSO proof**, the extension edited it to **Connect SSO proof — extension edit**, and CLI read back that edit and the original synthetic login password. Separate create/delete/sync passed. After a full stock-Vere restart, CLI still locally unlocked, synchronized and decrypted the extension edit. The extension explicitly synchronized and displayed a newly created **Post-restart synchronization proof** item, demonstrating fresh server access; that temporary marker was subsequently deleted.

Connect owner revocation then caused official CLI sync failure and logged the extension out on its next explicit sync. Cached data is not erased by server revocation. See [revocation evidence](native-revocation.json).

Visual evidence, inspected at full rendered size:

- [Actual CLI owner consent](cli-owner-approval.png)
- [Actual extension owner consent](extension-owner-approval.png)
- [Extension local-unlock screen after SSO](extension-sso-locked.png)
- [Extension editing the CLI-created item](extension-edited-item.png)
- [Fresh post-restart cross-client synchronization](extension-post-restart-fresh-item.png)
- [Extension login screen after revoked sync](extension-revoked.png)

## Security and lifecycle checks

[Adapter contract](adapter-contract.json): wrong PKCE, callback, client and requested scope; reused/expired code; access expiry; vault/document token isolation; wrong refresh client; six overlapping refresh requests returning one exact rotation; predecessor revocation during grace; reuse after grace invalidating the family; Connect revocation checked before cached response; unauthenticated/wrong-Origin/wrong-CSRF consent rejection. Expiry tests waited for actual wall-clock expiration.

[Restart](restart.json): full stock-runtime stop/start completed inside the five-second retry window and returned the identical persisted refresh response. Official CLI then synchronized/decrypted preserved data.

[Resource revocation](resource-revoke.json): another local resource cannot spoof the caller or revoke a foreign session. Own-resource revocation and absent-session idempotence pass. [Incomplete scopes](partial-scope.json): owner-approved `api` alone and `offline_access` alone reject login and release their newly created grants.

[Pending exchanges](pending.json): suspend the actual Connect desk, hold a real adapter HTTP exchange, then exercise both 30-second Behn timeout and adapter reload. Each returns retryable HTTP 503; resuming Connect produces a late result whose grant is revoked. No extra live Connect session remains.

[Storage](hardening.json): stale revisions return 409; 256 KiB request, 64 KiB stored-cipher, 4 MiB aggregate and 1,000 cipher limits were exercised against Gall. Soft-deleted entries still consume count; hard deletion frees it. [Soft-delete metadata](soft-delete-bound.json) cannot exceed the cipher-byte bound and a rejected mutation leaves the item intact. All disposable capacity-test items were removed.

The shipped enrollment JavaScript was also exercised with WebCrypto and simulated transient endpoint failure: retry reuses matching registrations and refuses unrelated registrations. This retry test is a browser-API harness, distinct from the actual initial enrollment UI run.

[Official negative tests](official-negative.json): the unmodified CLI's ordinary password login stops at the SSO-only prelogin message; a wrong-state callback to its actual loopback listener makes SSO fail. Private client output is retained locally, not included in this bundle.

## Reusable Connect and regression evidence

The independent `grant-probe` notes resource uses the same registration/exchange/scry/revoke contract, with its own scopes and callback. [Generic contract evidence](generic-contract.json) covers wrong-client/PKCE/callback denial, single-use codes, live resource isolation, owner revocation, and unchanged strict refresh-reuse behavior for ordinary document clients. The existing public Swift notes consumer also passes.

The final generic implementation passed all 74 real Hoon tests. Web typechecking/build and 19 codec tests passed. Protocol fixtures and OpenAPI validation passed: 27 routes, 14 schema fixtures. Swift SDK: 68 tests; independent Swift notes consumer: 2 tests. Existing tooling: 61 tests. A first tooling run encountered an existing ephemeral-port selection edge above the allowed port block; the unchanged rerun passed. No assertion or safety check was weakened.

The existing live HTTP suite is run by `test_connect_regressions.py` with fixture paths/control substituted, retaining its assertions. Native Eyre's redirect needed the dedicated certificate passed to the public-info test, and the stock control socket's hexadecimal clock needed decimal rendering for the existing minute-bucket test. Those harness issues were corrected before rerunning the affected suites. All **43** assertions/tests passed with no skips; module counts are in [Connect regressions](connect-regressions.json).

Review found and fixed grant release on logout/replay, abandoned exchanges, partial scopes, retry-safe registration, and storage bounds. Generic `connect-auth.hoon` remains byte-identical to the saved baseline. Contract copies and generated adapter assets are checked by `source_checks.py`.

## Journal and active-state audit

[History audit](history-audit.json) records **5,462** decoded events (365–5826), zero decode failures, zero known-secret matches, active-state results and positive controls. The audit searches the full LMDB at all eight bit offsets, then decodes literal atoms from input EVENTS beginning at the first synthetic account input. It checks the known synthetic password, derived master key, Bitwarden authentication hash (raw/base64/form encoding), and captured unwrapped enrollment user/RSA private keys. Active Connect and adapter Gall states are exported and checked separately. Native Hoon HS256 output matches independent Python HMAC-SHA256.

The audit deliberately proves it can find the encrypted user-key envelope, owner cookie and issued access token in decoded events. These, along with authorization codes, refresh tokens, email and ciphertext metadata, remain journaled. Known-value absence is evidence for exercised flows, not proof about arbitrary client actions/encodings. Earlier kernel boot events are raw-scanned rather than decoded. Wrapped account keys can still support offline password guessing; removing an authentication hash from this workflow does not remove that property.

## Limits and reproducibility

This remains a one-account synthetic-data preview with explicit sync. Unsupported account lifecycle and password-verification actions may send sensitive material before Gall rejects them; they are excluded from the no-authentication-hash workflow claim. No real accounts, recovery/migration, attachment/organization/Send/passkey workflows, production hosting, real-device coverage or broad client-version compatibility is claimed. Existing alpha qualification gates remain open. iOS sources were unchanged; a new full iOS/alpha release qualification was outside this adapter's acceptance scope.

[Setup, test and audit instructions](../README.md) identify client, certificate, WebCrypto, Python audit and fixture prerequisites. The documented setup orchestration was executed successfully against the preserved owned fixture after the initial fresh boot. Browser installation is pinned to Playwright 1.62.1 / Chrome 151; the newer web tooling otherwise selects Chrome 156. The package script creates a deterministic source archive with per-file hashes under `integrations/bitwarden/dist`, excluding private piers/profiles, downloaded clients and caches. It does not overwrite alpha release archives. No branch, commit, push, PR or external message was created.

Operational incident: an interrupted setup/control run coincided with stock Vere logging `newt: write failed broken pipe`, an external fault at `0x78`, and a libuv stack before exiting. The recorded process was verified absent; only its stale owned control socket was removed. The same pier restarted successfully, setup completed, and token/sync/signature/journal checks passed afterward. No runtime patch or safety bypass was made. This remains a pinned-runtime operational limitation, separate from the deliberately tested clean/crash restart assertions.

Responsive verification: the served enrollment and generic resource consent pages passed at 390×844 with visible controls and no horizontal overflow. Screenshots [enrollment](enrollment-mobile.png) and [consent](consent-mobile.png) were visually inspected; real owner denial cleaned up the test consent.

Delivery state: the dedicated browser was closed and the owned runtime was stopped cleanly after the final audit; the pier, private profiles and evidence are preserved. Source packaging passed two-build equality, all 324 per-file digest checks, and a scan for known private fixture password/master-key/cookie/token/session values. The original fixtures remain outside this task’s control paths.
