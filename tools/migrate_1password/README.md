# 1Password → Urbitwarden migration and verification

This local command-line tool combines a desktop **1PUX export** with **existing passkeys transferred by the official iOS Credential Exchange flow**. It creates usable vault items, uploads documents and attached files, preserves the original export metadata, and downloads the resulting content to verify it. It never invokes a 1Password API, edits 1Password, deletes a destination item, purges a vault, or removes your input exports.

**This is not an unattended passkey extractor.** Apple requires you to initiate the mobile transfer. A 1PUX export contains no passkey private keys, so an export alone cannot prove that all source passkeys are present. Source scope, passkey inventory, website sign-ins and cross-device checks are explicitly owner-reviewed; the report labels those attestations separately from machine comparisons. Until they are complete, the tool returns a nonzero exit status. A successful report means **complete against the reviewed inputs**, not an independent audit of everything still held on 1Password's servers.

## Requirements

- macOS or Linux, Python 3.11+, and the dependencies in `requirements.txt`.
- An unmodified official Bitwarden CLI **2026.10.0 or compatible**. Its command interfaces were checked against the official release binary and source; the tool includes archived and trashed identities in reconciliation. Do not substitute a shell script supplied by an untrusted party.
- An existing Urbitwarden account, Connect SSO, a trusted HTTPS server URL ending in `/apps/urbitwarden`, and its local vault password. The URL must be reachable from the computer and phone. Do not re-enroll an existing vault.
- 1Password and Bitwarden on an iOS/iPadOS 26+ device. The Bitwarden mobile app must already be connected to this same Urbitwarden account.
- A 1PUX version 3 desktop export for **each source account**, covering the vaults you intend to move. The export must include its `files/` members. Keep source edits paused during the migration, or make a fresh export and a new workspace.
- A new local private work directory outside source control and cloud-sync folders, preferably on an encrypted volume. Exports contain plaintext secrets. The tool's temporary uploads also contain plaintext until the official CLI encrypts them. Files use mode 0600 and directories 0700. Reports contain counts and opaque identifiers; the private inventory/review files include titles and metadata.

No Bitwarden cloud account, API key, proxy, custom cryptography transport, or changes to the Urbitwarden server are required by this tool. The official CLI performs all vault encryption and authenticated server requests. The target's passkey, attachment and mobile behavior must still work on the actual installation; source compatibility is not evidence of a completed live migration.

## Status and validation

The source and offline checks are recorded in [VALIDATION.md](VALIDATION.md). They do not establish a completed migration into a live vault. Select and verify the destination installation before beginning. Source coverage, iOS passkey transfer, actual website sign-ins and cross-client sync remain part of the owner workflow below.

## Setup

Run from this directory. Put the virtual environment outside the repository:

```sh
python3 -m venv /private/tmp/urbitwarden-migration-venv
/private/tmp/urbitwarden-migration-venv/bin/python -m pip install -r requirements.txt
```

Use that Python path for the commands below. `python` is shorthand for it in the examples. Install the official CLI using [Bitwarden's instructions](https://bitwarden.com/help/cli/). `--bw /absolute/path/to/bw` selects an explicit executable for each online command.

Before starting, make a recoverable backup of the destination using the repository's [backup guide](../../docs/backup.md). This tool only creates or explicitly enriches mapped records and never rolls back by deleting data. Keep 1Password available throughout verification.

## Workflow

### 1. Inventory the desktop exports locally

In 1Password for Mac use **File → Export**, selecting **1PUX** for each account. Do not use CSV. Then:

```sh
python migrate.py prepare \
  --source /private/path/account-one.1pux \
  --source /private/path/account-two.1pux \
  --work-dir /private/path/migration-review \
  --server https://your-ship/apps/urbitwarden \
  --email your-enrolled-email@example.com
```

`prepare` does not contact either service. It writes `inventory.json`, `review.json` and `state.json` into a new work directory. It refuses malformed archives, duplicate source identities, traversal paths, symlinks and ambiguous/missing document files. The source identity combines **account ID + vault ID + item ID**; item IDs alone are not globally unique.

Compare inventory counts and scope with the source accounts, including archived items and every vault you intend to migrate. Server-side item revision history, deleted/recently-deleted items omitted by 1Password's export, and shared-vault permissions cannot be certified by this tool. Do not mark scope reviewed if those are part of your requirement and are absent. Exported password history is preserved in full.

### 2. Transfer the actual passkeys on the iPhone/iPad

In 1Password use **Settings → Advanced → Start Export** and choose Bitwarden. Confirm the destination is your **Urbitwarden account**. Do this for every relevant source account and verify the mobile transfer's selected scope. It can import ordinary items too; unmapped mobile items are left intact. This tool enriches the explicitly mapped passkey records and does not guess which other mobile duplicates can be deleted.

The current Bitwarden CXP parser selects the first passkey per exchanged item. If the source has multiple passkeys in an item, verify that each one actually arrived; missing keys must be resolved through the official export flow before proceeding. The tool supports multiple transferred passkeys for a source record by representing each in a separate usable login. It validates the P-256/ECDSA private keys supported by the inspected CXP implementation and stops on other algorithms. It cannot recover a key that the source app did not export.

### 3. Connect the dedicated CLI profile and capture the passkey baseline

```sh
python migrate.py connect --work-dir /private/path/migration-review
python migrate.py capture-passkeys --work-dir /private/path/migration-review
```

The tool uses a dedicated `bw-profile/` under the work directory, verifies the exact server and enrolled email, and subsequently binds its immutable account ID. Sign in through **Enterprise SSO**, organization `urbit-vault`, and approve Connect. Unlock uses a local hidden password prompt. It does not enable password login or print/save the CLI session. Later invocations may request local unlock again. Advanced users may supply a session in `URBITWARDEN_MIGRATION_SESSION` for this dedicated profile; do not put it in command arguments or the review file.

`passkey-catalog.json` lists destination item IDs, credential IDs, relying-party IDs and fingerprints, **not private keys**. This is a destination inventory, not proof of source coverage. Capture again if the mobile transfer was incomplete, but only before any `apply` writes. A later recapture invalidates the plan.

### 4. Review explicit source-to-passkey and file associations

Edit `review.json` in the private work directory (keep permissions 0600). Set `source_scope_reviewed`, `representations_reviewed` and `passkey_inventory_reviewed` to `true` only after checking those things. Set `expected_passkey_count` to the number of source passkey occurrences, including all intended accounts. If there are genuinely none, explicitly use `0` and an empty mapping.

Use the source IDs in `inventory.json` and destination IDs in `passkey-catalog.json`:

```json
{
  "source_scope_reviewed": true,
  "representations_reviewed": true,
  "passkey_inventory_reviewed": true,
  "expected_passkey_count": 1,
  "cross_client_sync_verified": false,
  "passkeys": {
    "source:THE_FULL_SOURCE_HASH": [
      {
        "item_id": "DESTINATION_ITEM_ID",
        "credential_id": "CREDENTIAL_ID_FROM_CATALOG",
        "sign_in_verified": false
      }
    ]
  },
  "file_owners": {}
}
```

Every unmapped archive file appears in the generated `file_owners` object with a null value. Replace it with a list of source IDs from the inventory, or the source archive's `archive:...` identity for account-level assets. Explicit document IDs and file paths are resolved automatically. The tool never guesses by a matching title. An unknown association blocks transfer until reviewed.

### 5. Plan, then apply or resume

```sh
python migrate.py plan --work-dir /private/path/migration-review
python migrate.py apply --work-dir /private/path/migration-review
```

Review `plan.json` before applying. It shows create/update counts and representation changes. The plan binds the source archives, destination account, reviewed mappings, captured passkey material and preexisting destination content. A different source file, changed mapping, missing credential or concurrent item edit stops the operation. Sign-in/cross-device attestations can be added after applying without invalidating the transfer plan.

`apply` keeps a write-ahead journal. After an interrupted response, run **the same command with the same workspace**. Stable encrypted item markers identify completed item writes; uploaded files are identified by their parent item, filename and downloaded bytes. A changed or ambiguous attachment is not accepted as a successful retry. Do not start a second workspace to retry the same transfer. The journal is protected by a process lock.

## Representation and preservation

- Logins/passwords, cards, identities and SSH keys use native Bitwarden item types. SSH private keys are converted to OpenSSH with the same key material; their public keys are checked cryptographically.
- Documents become named secure notes with their actual file attached. Other 1Password categories become secure notes with their complete fields. These are explicit representation changes in the plan, not claims of identical app behavior.
- All source sections and web-form values are retained as custom fields. All tags are retained together, and each source vault maps to a deterministic folder. Multiple TOTP fields remain available in custom fields; Bitwarden's native login TOTP slot holds the first.
- Exported password-history entries are not truncated to five. Archive status is retained. Original timestamps, category metadata, URL labels, links, custom field structure and other exported properties also remain in the exact original metadata files.
- Every archive's **original `export.data` and `export.attributes` bytes** are encrypted attachments on a dedicated metadata item. This supplementary copy preserves source structure that cannot be represented exactly in Bitwarden. It is not a replacement for transferring usable credentials and individual uploaded files.
- Custom icons are preserved as attached files; Bitwarden will not necessarily use them as its displayed icon. Shared-vault access rules and 1Password-specific services are not recreated in this personal vault.
- Existing mapped CXP login records are enriched only when their credentials agree with the desktop source. Their extra fields, URLs and notes are retained. If one CXP record contains several passkeys or is shared by mappings, it is left intact and separate destination logins are created. Unmapped existing records and mobile duplicates are never deleted.

## Verification and completion

```sh
python migrate.py verify --work-dir /private/path/migration-review
```

Verification performs a fresh sync, compares native content and every mapped passkey against the expected fingerprints, checks unique item associations, and **downloads every attachment** to compare its exact size and SHA-256 with the original. Metadata files are verified byte for byte too. Missing, truncated, reassigned or corrupted data fails the report; an API success response alone is insufficient.

Use each transferred passkey to sign in with **Bitwarden selected as the provider**, then set that mapping's `sign_in_verified` to true. Confirm the resulting items and files can be read after sync on your other client and set `cross_client_sync_verified` to true. These are owner observations, explicitly labeled as such. Re-run `verify`.

`report.json` contains no passwords, private keys or tokens. `complete: true` means the supplied data passed machine checks **and** the required source/device observations were affirmed. It cannot prove that an unexported item/passkey exists nowhere in 1Password. Keep the source account intact and keep a separate encrypted recovery backup. The tool never deletes your exports; remove plaintext exports/private workspace yourself only after deciding the migration is accepted and recovery copies are usable. Normal temporary uploads are removed even on errors; a killed process's explicitly journaled upload directory is removed when the workspace is resumed. If the tool is never resumed after a crash, that private scratch data remains until you remove the workspace.

Exit codes: `0` command succeeded (for apply/verify, complete against reviewed inputs); `2` unresolved input, verification or operational error; `130` interrupted. `prepare`, `capture-passkeys` and `plan` succeeding do **not** mean the migration is complete.

## Development validation

```sh
python -m unittest discover -s tests -v
python migrate.py --help
```

The tests use public-shaped local archives and a stateful CLI boundary double; they do not read a real vault, start a ship or constitute live iOS/Urbitwarden acceptance. Source contract references:

- [1Password export](https://support.1password.com/export/), [1PUX format](https://support.1password.com/1pux-format/)
- [Bitwarden mobile import](https://bitwarden.com/help/import-data/), [CLI](https://bitwarden.com/help/cli/)
- [Official CLI item creation](https://github.com/bitwarden/clients/blob/desktop-v2026.10.0/apps/cli/src/vault/create.command.ts)
- [Official CLI editing](https://github.com/bitwarden/clients/blob/desktop-v2026.10.0/apps/cli/src/commands/edit.command.ts)
- [Passkey serialization](https://github.com/bitwarden/clients/blob/desktop-v2026.10.0/libs/common/src/models/export/login.export.ts)
- [CXP import](https://github.com/bitwarden/sdk-internal/blob/main/crates/bitwarden-exporters/src/cxf/import.rs)
