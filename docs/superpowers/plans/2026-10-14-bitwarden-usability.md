# Native Bitwarden usability implementation

> Historical plan, retained from the original Connect checkout. Its original paths and terminology describe that implementation period, not the current repository layout or execution authorization. The backend is the native Bitwarden desk. See [the repository split record](../../repository-split.md) for current paths, latest-Connect dependency handling and verification boundaries.

User-authorized scope: normal installation/onboarding, backup and recovery, everyday official-client workflows, folders/migration, and desktop/mobile support. Build on the existing native personal-vault desk. Authorization tokens retained in history cannot decrypt the vault or reveal passwords; this is an accepted limitation and not a blocker.

## Invariants

Stock Vere/Gall/Eyre only for the backend. Unmodified official clients. Connect stays generic. Preserve 60-second Bitwarden access tokens, 30-day absolute Connect grants, five-second retry grace. Do not modify the two assigned token derivation blocks. Do not run credential-state/journal inspection or restricted adversarial security validation. Ordinary functional and native compatibility tests remain required.

Preserve original demo, real ships, unrelated Hermes/prototype work and other client profiles. Use owned synthetic fixtures and dedicated client environments. No journal pruning, live identity cloning or real-ship deployment without an exact authorized target. Existing private GitHub commit/push authorization applies to the completed source.

## Work and acceptance

1. Correct current documentation: retained authorization tokens do not decrypt/read passwords. Add clear normal enrollment/enrolled/error UI with password confirmation and client setup information. Preserve browser-only key creation and wrapping. Test states, render desktop/mobile layouts and exercise real flow.
2. Extend exact official desktop/mobile client IDs and callbacks from pinned upstream source. Keep code exchange and token derivation unchanged. Provide root-compatible native UI routing without displacing existing ship apps. Verify official desktop and mobile SSO/local unlock/sync, plus existing CLI/extension regression. Do not equate simulated requests with native app proof.
3. Implement personal folders and smallest official import route, preserve encrypted payloads and bounded state. Exercise official export and common item types; fix only missing compatible operations. Test native APIs, accepted-size boundaries and official round trips.
4. Implement explicit real-ship deployment/update and stopped-pier backup/isolated restore tooling. Preserve existing unrelated desks/certs and verify manifests/selected identity. Demonstrate package install and restore on an owned synthetic ship. Supply native HTTPS certificate and renewal instructions without another backend service.
5. Demonstrate controlled-site autofill/save/update, browser return, cross-client sync, folder/item round trips and backup reopening. Final scoped correctness review, source-bound package/evidence, cleanup owned resources, commit/push.

## Execution ownership

Parent owns Hoon agent, generated bundle, integration runtime, documentation and final acceptance. Onboarding worker owns web source and its new test. Deployment/recovery worker owns new deployment/backup scripts/tests and install/backup docs. Client workers prepare only isolated official distributions/simulators; research worker supplies exact upstream protocol contracts. No concurrent CLI use or runtime mutation.

## Verification boundary

Record actual native tests and app interaction separately from source checks, mocks and untested platforms. Preserve excluded checks as pending. If an end-user dependency cannot be fulfilled after reasonable attempts, report the exact remaining gap rather than claiming complete usability.
