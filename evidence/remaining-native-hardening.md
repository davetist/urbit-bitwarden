# Remaining native hardening — scoped implementation evidence

Date: 2026-10-14. Target: current `urbit-connect` source and its owned `review-fixes` fake ship. Backend: stock Vere 4.6, Kelvin 408, native Gall/Hoon/Eyre. No external backend/service/library or client fork was introduced.

## Implemented

- Native Behn expiry for persisted token retry responses; reload pruning and re-arming; stale-wake protection; cache cleanup when a checked Connect grant is invalid. The five-second retry duration, state layout and token derivation remain unchanged.
- Selected-fixture routing in ten helpers, including audit dependencies and CLI evidence/item IDs. The original demo is preserved.
- A fixture startup correction: TCP TIME_WAIT no longer blocks restart, while live TCP listeners and bound UDP ports are still rejected.
- Separate ordinary lifecycle/compatibility tests. The pre-existing authorization/replay assertions remain intact in their original suites.
- Functional-only browser mode, without request/key capture, and an explicit [client support boundary](../docs/client-support.md).

## Executed evidence

| Check | Result |
|---|---|
| Fixture routing and ownership | 6 tests pass; 12 helper subcases inspected. Initial regression found ten helpers bypassing the selected fixture. |
| Restart port guard | 3 real-socket tests pass: closed TCP connection reusable; active TCP/UDP collisions rejected. The original code reproduced `EADDRINUSE` on TIME_WAIT. |
| Native cache lifecycle | 7 actual Hoon tests pass using an instantiated agent with inert dummy state. Expiry, exact deadline, orphan cleanup, preserved response/re-arming, idle wake, stale wake and early wake are covered. No live credential state was inspected. |
| Legitimate refresh compatibility | Six concurrent retries returned identical responses. The batch took 0.141 seconds in this fixture; this is an observation, not a performance target. |
| Runtime restart | A 1.259-second full stop/start preserved the identical response inside grace; subsequent sync passed. Current refresh also worked after ordinary idle cache expiry. |
| Native item lifecycle | Four delete/restore cycles passed with exact restore responses, idempotency, same-second monotonic revisions and preserved ciphertext. |
| Capacity | A 65,536-byte item in a vault at the exact 4 MiB payload limit remained deletable/restorable without truncation; count and unrelated-growth limits remained enforced. |
| Official CLI | SSO exited 0; local unlock, encrypted create, trash, restore, sync/decrypt and lock/re-unlock passed using official 2026.9.1. |
| Official extension and cross-client flow | Official 2026.9.3 completed SSO/local unlock, decrypted a CLI-created item, edited it, and the CLI read back the changed item. The extension also deleted that item and restored it from the bin. [Edit screenshot](review-fixes/functional-extension-edit.png), [restored item](review-fixes/functional-extension-restored.png). |

Machine-readable results: [cache](review-fixes/cache-lifecycle.json), [refresh/restart](review-fixes/refresh-compatibility.json), [native lifecycle](review-fixes/functional-lifecycle.json), [official CLI](review-fixes/official-cli-lifecycle.json).

The Hoon regression tests failed against the old agent before the implementation change. During test development, Ford import ordering and typed card-list construction required correction before native compilation succeeded. Official CLI JSON omits some null fields; the restore test checks both the absence of a deletion timestamp and actual removal from the trash. A first client test overlapped another CLI process; final CLI lifecycle verification ran without overlapping CLI commands.

## Deliberately excluded

- The two previously assigned token-derivation fixes. Both generic Connect source files and the Bitwarden JWT/refresh derivation block were compared to the preserved baseline and remain unchanged.
- Credential-state inspection, journal-secret scans, expanded sensitive-action transmission checks, and adversarial authorization/replay verification. These remain pending under the user's restriction.
- Broad desktop/mobile compatibility, unsupported account lifecycle features, deployment to real ships and production qualification.

The old [acceptance report](report.md) is historical evidence. It is not a fresh security attestation for this source. Cache cleanup does not erase older journal events, stopped snapshots or backups.

Independent static correctness review found no Critical/Important defect. Its guard-order finding was fixed: the review-only CLI lifecycle helper now refuses the demo fixture before importing any CLI data. A blocked-import regression failed first and then passed. Restricted security review/validation remained excluded.

## Package and final state

The source archive was extracted into a separate temporary directory, its manifest verified, and the extracted Bitwarden desk installed into the owned review ship. Seven native cache tests and the complete official CLI lifecycle passed against that installed desk. The official extension then explicitly synced a new CLI edit and displayed it: [inspected package-sync screenshot](review-fixes/functional-extension-package-sync.png).

This verifies archive-to-runtime installation using the existing pinned runtime, dependencies and enrolled review fixture. It is not a fresh-machine setup or fresh enrollment result. Final packaging adds the updated report and evidence; the installed desk and tested helper bytes remain identical. The archive includes its file manifest and has a separate SHA-256 sidecar.

Locally generated [source archive](../dist/connect-bitwarden-sso-source.tgz) · [SHA-256](../dist/connect-bitwarden-sso-source.tgz.sha256) · [package verification record](review-fixes/native-hardening-package.json).

The owned review browser and fake ship were stopped, with process termination checked. Their pier and client profiles are preserved. The original demo and real ships were not modified. At the end of the functional run, Git had been initialized on `main` without staging, commits or a remote. The owner subsequently authorized committing to the private `davetist/urbit-connect` repository; its existing history and copyright notice are preserved. Private fixtures, environment files and caches remain ignored.

The authorized implementation and ordinary functional checks are complete. The excluded token fixes and restricted security validation remain pending; unsupported client actions have no new pre-transmission guarantee.
