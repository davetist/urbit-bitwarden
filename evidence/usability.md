# Native Bitwarden usability verification

**Historical 2026-10-15 record.** For the current standalone desk pair, use the [2026-10-16 rerun and readiness assessment](current-2026-10-16/assessment.md).

Verified 2026-10-15 on the owned synthetic `review-fixes` ship with stock Vere 4.6. Connect remains the generic authorization service; the Bitwarden desk owns encrypted personal-vault storage and client protocol responses. No backend service, runtime patch or production library was added.

## Delivered behavior

- Native setup and API routes live under `/apps/bitwarden`, preserving the ship home page and unrelated bindings.
- Setup handles new/existing accounts, password confirmation, errors/retry, all four official client registrations and explicit migration of the old extension callback. Generic Connect supports exact registered private callback schemes without Bitwarden-specific policy.
- Personal folders support create/read/rename/delete; deleting a folder detaches its items. Atomic personal import preserves folder relationships, reuses only folders that already existed and assigns new IDs otherwise.
- Personal login, secure note, card and identity data round-trip through official client encryption. Import alone accepts a 6 MiB HTTP body; retained cipher limits remain 1,000 items, 64 KiB/item and 4 MiB aggregate. Folder limits are 1,000 folders, 64 KiB/folder and 1 MiB aggregate.
- The official iOS response contract includes profile `creationDate` and configuration `server.url`. Existing-account migration uses the pre-upgrade revision when no historical creation date was retained.
- Explicit source-manifest deployment/update, native HTTPS certificate replacement, stopped-pier backup and isolated restore are documented in [installation](../docs/install.md) and [recovery](../docs/backup.md).

## Demonstrated clients

| Client | Actual functional evidence |
|---|---|
| Official CLI 2026.9.1 | Fresh SSO at the new URL; local unlock; all four personal item types; folder create/rename/delete; JSON export followed by removal and official import restoring item contents and folder relationships. [Evidence](review-fixes/official-cli-usability.json). |
| Official extension 2026.9.3 | Fresh SSO/callback, local unlock, automatic initial sync, explicit sync, native-popup autofill on a controlled login page, saved name/password edit and successful autofill afterward. CLI independently decrypted the edit. [Evidence](review-fixes/official-extension-usability.json), [readback](review-fixes/extension-edit-readback.json), [form result](review-fixes/official-extension-autofill-pass.png). |
| Official signed macOS desktop 2026.9.1 | SSO, normal browser-to-app OS callback, local unlock and automatic initial sync; secure-note creation/edit/view. CLI independently decrypted the saved note. Official Electron sandbox remained enabled. [Evidence](review-fixes/official-desktop-usability.json), [screenshot](review-fixes/official-desktop-vault.png). |
| Official-source iOS 2026.9.1 (3533), Simulator | Ship login, SSO/callback, local unlock, automatic initial sync, existing login view, secure-note creation/title edit, explicit sync of another client's item, app restart and local re-unlock. CLI independently decrypted the edit. No application source changed. [Evidence](review-fixes/ios-functional-progress.json), [readback](review-fixes/ios-cli-readback.json), [screenshot](review-fixes/official-ios-reopened-vault.png). |

The iOS build is a locally compiled official release, not the App Store binary. Android has source-contract coverage only. Physical devices, other desktop operating systems and other client versions were not qualified. Password-protected exports and automatic save/update suggestion banners were not exercised; local JSON export, explicit extension editing and autofill were.

## Automatic sync

Automatic initial sync was demonstrated in the extension, desktop and iOS. The native revision/sync endpoints also support the official clients' existing periodic and lifecycle checks. Their six-hour desktop/extension fallback and 30-minute mobile foreground freshness thresholds are confirmed in pinned source, not by elapsed-time tests in this run. Immediate cross-device push remains unsupported under the stock-runtime/no-external-services constraints. See [the exact client behavior and transport evidence](../docs/client-support.md#automatic-sync-and-immediate-updates).

## Native and tooling verification

- Native namespaced API/config, folders, all four item types and import: [API result](review-fixes/usability-api.json).
- Large import, existing/new folder IDs, the generated-ID collision regression, bulk/all folder detachment and eight atomic rejection/bounds cases: [folder/import result](review-fixes/folders-import-functional.json).
- Three generic callback tests; seven native cache tests; four native lifecycle cycles.
- Thirteen real-browser onboarding cases and the enrollment retry harness. Native-served 390px setup/consent controls had no horizontal overflow: [responsive result](review-fixes/responsive.json).
- Eleven deployment tests, seven backup tests, six fixture tests and three port-readiness tests. New Python tooling parses for Python 3.10. Source architecture checks and deterministic asset/archive checks passed.
- Manifested source was installed through native local control. Full stopped-pier backup was hashed, restored to an absent directory, booted and used by the official CLI to unlock/sync/decrypt a known item. The original stopped pier was preserved; source and restore never ran concurrently. [Deployment](review-fixes/native-packaged-deploy.json), [recovery](review-fixes/native-recovery-functional.json).
- Independent ordinary correctness review found three functional defects; regression tests reproduced them and fixes passed. Final source review found no remaining concrete findings in that scope.

## Preservation and boundaries

The 60-second access lifetime, 30-day absolute Connect grant and five-second retry grace are unchanged. Protected authorization/token-derivation source blocks were compared with the task baseline and are unchanged. The two assigned security fixes and restricted credential/journal/adversarial validation were not performed.

Retained authorization tokens cannot decrypt the vault or read passwords. They can authorize operations on encrypted data while valid; history retention remains the explicitly accepted limitation, not a usability blocker.

The test-only Simulator and its certificate trust were removed. Desktop native-host manifests and URL-handler state were restored. The disposable browser's Developer mode was returned to its original disabled setting. Task-created vault records and temporary plaintext export files were removed. Original demo data, unrelated projects and real ships were preserved. Test build/distribution artifacts and the stopped recovery source remain private local files, excluded from the source package.
