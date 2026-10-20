# Validation record — 2026-10-19

The tool was developed without reading a real 1Password export, authenticating to either real vault, changing a ship, or moving the owner's credentials. This record describes software verification, not an executed personal migration.

- **32/32 offline Python tests passed from the installed repository location**, using `python -m unittest discover -s tests -v`. They exercise archive integrity, account/vault/item identities, complete exported history, native credential conversion, SSH-key equivalence, files containing binary zeroes, passkey key-material comparison, multiple passkeys, account binding, concurrent content changes, corrupted/missing destination data, process-boundary stdin/binary handling, crash recovery and completion prerequisites.
- The terminal workflow is exercised through a stateful CLI subprocess double, including an archived item. The double does not establish official-client encryption, live SSO, server storage, or phone behavior.
- Bitwarden's public 28-item sanitized 1PUX example was parsed and converted without conversion errors. Its missing document file was flagged instead of skipped. The example was only used as an additional development input and is not bundled.
- The official **CLI 2026.10.0 macOS arm64** binary was downloaded from its public release. Its release-reported archive SHA-256 was verified: `062c880508678b8d936ab2522a3a1e92d60f52b5c534e71406e9b47329e95207`. Version and command-help checks confirmed archived/trash flags, stdin item edits and raw binary attachment output. Its unauthenticated default public config lookup failed in the network-restricted check environment; command-help checks still exited successfully. No authenticated CLI workflow was exercised.
- An independent read-only review found two correctness defects: archived items were omitted from listing, and marker adoption could remove an unreviewed destination passkey. Both received failing regression tests and fixes. Discovery now includes active, archived and trashed identities; target updates reject unexpected passkeys.
- Python syntax checks passed for all 11 Python files; new-file whitespace checks, local documentation links and CLI help passed. No native/backend changes require compilation or ship-fixture runs.
- The repository's existing `npm test` suite is **not passing**. Its first run also encountered a sandbox browser-launch restriction. Re-running the unchanged `HEAD` source in an isolated directory with browser launch permitted produced **6 passes / 8 failures**. The tested web assets, test files and package definition were byte-identical to the working copy, and none were changed by this tool. These existing tests still expect eager four-client registration and legacy client-setup controls. They are outside this standalone Python tool's changed behavior and were not modified to obtain a green suite.

Existing JavaScript failures reproduced on unchanged `HEAD`:

- `scripts/test_enrollment_retry.mjs` — expected four registrations, observed zero.
- `enrollment retries reuse registrations and leave an existing Connect issuer untouched`
- `explicit client setup adds desktop and mobile and enables a matching disabled registration`
- `client setup refuses a conflicting registration before changing any registration`
- `client setup configures an unconfigured Connect once and refuses a different issuer`
- `a known legacy browser callback requires an explicit update before replacing its registration`
- `an unknown callback mismatch cannot be replaced by the legacy-update action`
- `an unenrolled vault can explicitly update a legacy registration and retry enrollment`

## Still requires the actual source/device workflow

The owner must produce the exports, perform the iOS CXP handoff and review source coverage. Real Connect SSO, attachment uploads/downloads against the selected moon, website passkey sign-ins and cross-client synchronization must be exercised during the actual migration. The tool's report separates those owner attestations from machine comparisons, and refuses completion while required observations or data are missing.

Source scope and passkey completeness cannot be independently inferred from 1PUX or a destination-only catalog. Shared permissions, unexported server revision history and other 1Password product behavior are outside what this personal-vault content migration can reproduce. These limits are part of the review, not silently counted as transferred.
