# Back up and restore the Urbitwarden desk

## Automated encrypted vault backups

`scripts/vault_backup.py` captures the enrolled vault from a running ship using a single local Gall scry. It does not stop the ship or copy its Ames state. The portable snapshot contains the account's wrapped encryption keys and KDF settings, encrypted items (including stored passkeys), folders, attachment storage and ID counter. It excludes Connect grants, HTTP credentials, vault sessions and token-signing keys.

The snapshot is encrypted with **age** in memory before an archive is published. The Pi needs only the public recipient; keep the private recovery identity on a separate trusted device and an offline copy. Recovery also needs the vault's original local master password. Neither the backup job nor the ship needs that password. A lost recovery identity or master password cannot be repaired by restoring the other one.

Requirements: Python 3, age, the updated Urbitwarden desk, and the pier owner's access to stock Vere's local control socket. The current native baseline is Vere 4.6 / Zuse 408. Cloud uploads additionally use rclone with a dedicated storage credential. The Pi's schedule uses its existing user systemd manager and must have lingering enabled to run after logout. This is independent of the Codex app and the Mac's sleep state.

Create the recovery identity on the recovery computer, with private directory/file permissions:

```sh
umask 077
age-keygen -o /private/recovery/recovery-key.txt
age-keygen -y /private/recovery/recovery-key.txt
```

Copy only the resulting **public recipient** to the Pi. Never put the private identity in the vault, on the Pi, or beside the cloud archives as its only copy.

Capture a manual snapshot as the pier owner:

```sh
python3 scripts/vault_backup.py create \
  --pier /absolute/path/to/pier --ship '~sampel-palnet' \
  --recipient age1YOUR_PUBLIC_RECIPIENT \
  --output /private/backups/first-vault.age
```

The output directory must be private (mode 0700). Published files are mode 0600. Existing files and symlinks are refused. Interrupted encryption never publishes a partial archive. No unencrypted snapshot file is created. Wrapped keys and encrypted vault data are temporarily held in process memory; snapshot size is consequently bounded by available host memory, including attachments.

For automatic capture, create a private configuration file containing these fields:

```json
{
  "pier": "/absolute/path/to/pier",
  "ship": "~sampel-palnet",
  "recipient": "age1YOUR_PUBLIC_RECIPIENT",
  "output": "/private/backups/vault",
  "remote": "vault-s3:YOUR_PRIVATE_BUCKET/vault",
  "rcloneConfig": "/private/config/rclone.conf"
}
```

The remote must already be authorized. For AWS S3, create a dedicated private bucket with Block Public Access enabled, ACLs disabled, server-side AES256 encryption, and versioning disabled (or suspended on an existing bucket). Use a bucket policy requiring TLS. To migrate an existing bucket, an administrator must remove its old objects, versions and delete markers once; suspending versioning alone does not remove existing history. Give the Pi a separate IAM credential with list access to the `vault/` prefix and read/upload access to `vault/*.age`, including multipart upload support. Do not grant object deletion, bucket administration, access to other buckets, or console login. The storage credential cannot decrypt the age archives.

A private (0600) rclone configuration for that credential is:

```ini
[vault-s3]
type = s3
provider = AWS
env_auth = false
access_key_id = YOUR_SCOPED_ACCESS_KEY_ID
secret_access_key = YOUR_SCOPED_SECRET_ACCESS_KEY
region = us-east-1
no_check_bucket = true
```

`no_check_bucket` prevents rclone from attempting bucket creation with the restricted key. The bucket must already exist. See [rclone S3 configuration](https://rclone.org/s3/) and [AWS S3 permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html). No browser session, Mac, master password, or private age identity is needed for scheduled uploads.

```sh
python3 scripts/vault_backup.py run --config /private/config/vault-backup.json
python3 scripts/install_vault_backup.py --config /private/config/vault-backup.json
python3 scripts/install_vault_backup.py --config /private/config/vault-backup.json --apply
```

The installer checks the exact live ship, completes a backup first, then enables a persistent timer at midnight and noon in Europe/Madrid, with up to 30 seconds of jitter. A lock prevents overlapping runs. The job keeps **one latest archive per destination**: local `latest.age` and remote `vault/latest.age`. Unchanged content reuses the verified local archive and its matching upload receipt. Changed content is encrypted to a temporary file, flushed, then atomically replaces the local archive; encryption failure leaves the previous archive intact. Legacy timestamp-named scheduler archives and their receipts are removed only after the new local archive is safely published. Unrelated files are left alone; use a dedicated output directory.

Uploads replace the single remote key, then download it and compare its encrypted-file hash before recording success. An offline run keeps the latest local capture and retries it next time. If the vault changes again while offline, the new capture supersedes the unsent older one. Receipts are tied to the exact destination and encrypted-file hash. For S3, disabled/suspended versioning is required so overwriting `latest.age` does not keep hidden older copies. The Pi needs no delete or bucket-administration permission for this. This policy deliberately retains no automatic history; an unwanted vault change replaces the previous backup at the next successful changed capture.

Omit `remote` and `rcloneConfig` for local-only capture. `status.json` explicitly records whether cloud upload is configured; a local-only success does not mean an off-site backup exists. Inspect failures and the latest completion with:

```sh
systemctl --user status urbitwarden-backup.timer urbitwarden-backup.service
journalctl --user -u urbitwarden-backup.service
```

A timer is not a guarantee that the last backup succeeded. The status file records the last successful completed run; a stale timestamp or failed service requires attention. The Pi credential cannot delete objects, but it can overwrite the latest archive. An AWS account administrator can delete backups. Keep the separate local copy and recovery material.

### Pause or retarget the scheduler

Pause the timer and stop any in-progress capture before changing the target:

```sh
systemctl --user disable --now urbitwarden-backup.timer
systemctl --user stop urbitwarden-backup.service
```

Keep the private configuration, public age recipient and separate recovery identity. For a different enrolled vault, update the exact `ship` and `pier` in the private configuration and review `output` and `remote` deliberately: the single-latest policy replaces the previous vault's latest archive at those destinations. Preserve any previous archive you still need separately before the first changed capture. Reuse the existing encryption keys unless you deliberately rotate them.

Run the installer without `--apply` to check the selected live target, then make a fresh manual `run --config ...`. Check its upload/readback result and independently verify the downloaded archive with the separate recovery identity. Enable scheduling with `install_vault_backup.py --config ... --apply` only after that verification; the installer itself requires another successful capture before enabling the timer.


### Restore into a fresh vault

Install the updated desk and native HTTPS on a **fresh, unenrolled vault** on the destination ship. Do not enroll an empty account first. Download the `.age` archive to the recovery machine and verify it there:

```sh
python3 scripts/vault_backup.py verify \
  --archive /private/recovery/vault.age --identity /private/recovery/recovery-key.txt
```

Run the restore where the destination's local control socket is accessible. The private recovery identity should remain on a trusted recovery host; for recovery onto another host, use a carefully scoped private operator channel rather than permanently installing that identity on the backup Pi.

```sh
python3 scripts/vault_backup.py restore \
  --pier /absolute/path/to/fresh-pier --ship '~other-ship' \
  --origin https://new-ship.example \
  --archive /private/recovery/vault.age --identity /private/recovery/recovery-key.txt
```

Without `--apply`, this decrypts/validates the envelope and checks that the destination vault is empty. Repeat with `--apply` to restore. Both the tool and the native atomic restore event refuse an enrolled/nonempty destination. Restoration preserves the wrapped account key and content; it generates a new signing key/security stamp, installs the destination origin, imports no old sessions or Connect authority, and disables automatic trash expiry to protect recovered records.

Configure the official client for the destination URL, authorize it through the destination's Connect, then unlock using the original local vault master password. This recovers the vault onto the destination's own current ship state; it does not roll back the source ship or reconnect a historical pier to Ames. The format is specific to Urbitwarden, not a direct Bitwarden/Vaultwarden import file.

Only credentials present at capture time can be recovered. Device-bound passkeys not stored in this vault are not included. Relying parties that enforce increasing legacy passkey counters may reject rolled-back counters; keep independent account recovery options for those services.

### Recovery verification

`test_vault_backup.py` covers encryption round-trip, tampering/wrong-key rejection, private publication, manual overwrite refusal, latest-only replacement, failed-encryption preservation, unchanged captures, offline retries and legacy cleanup. `recovery_fixture.py` and `test_vault_recovery.mjs` are explicitly invoked, disposable native recovery tooling; they do not use the real vault. The test uses fresh client profiles and a separate destination ship, imports a password and browser-created passkey with the official CLI, captures/restores the encrypted snapshot, and verifies a fresh browser WebAuthn challenge using the restored key against the original registration public key. Its authenticator is Chromium's virtual authenticator; it is not a claim that a physical authenticator or mobile client was tested. Record the actual run result separately.


A full stopped-pier backup preserves the Bitwarden account's wrapped key, encrypted vault, Connect authorization/configuration and all other ship state together. This avoids a partial application export that loses enrollment or key metadata. The backup utility copies files as opaque bytes: it does not inspect or decode journals, Gall state, credentials or vault contents. It runs on macOS/Linux with Python's standard library and stock Vere; no backup server or runtime change is added.

**A backup is private ship data.** It includes encrypted vault data and the ship's other private state. Journal history may contain authorization tokens that **cannot decrypt or read your passwords**. A still-valid token can authorize operations on the encrypted vault. That accepted limitation does not change session lifetimes or block ordinary use. Copies of a full pier still require ordinary host/backup access protection. File hashes detect accidental corruption; they are not encryption or a signature against someone able to replace the entire archive.

## Create and verify

1. Stop the chosen ship normally with `|exit`, Ctrl-D, or its existing ship manager. Stop/disable that manager's automatic restart for the duration of the copy. The utility never stops a process on your behalf.
2. Select the exact stopped pier, declared ship name and a new archive path outside the pier:

```sh
python3 scripts/backup.py create \
  --pier /absolute/path/to/your-pier --ship '~sampel-palnet' \
  --output /private/backups/sampel-palnet-2026-10-14.tgz
```

3. Verify the archive whenever it has been copied to another storage device:

```sh
python3 scripts/backup.py verify \
  --archive /private/backups/sampel-palnet-2026-10-14.tgz
```

The helper holds the same first-byte `fcntl` lock in `.vere.lock` that stock Vere uses, for the entire snapshot/hash/archive operation. A running ship is refused, and a concurrent runtime start cannot acquire that lock. An existing control socket is also refused instead of silently removed. It checks that source files stayed unchanged, verifies every archived file hash and size, and only then publishes a mode-600 archive. It refuses pier-data symlinks, special files, existing output paths and an output inside the source pier. The one supported symlink exception is the explicitly selected `.run`: its target must be a regular executable. That executable is copied into the archive as a regular `.run` file, whether its original target was inside or outside the pier. Restoring it never retains a link to an old host path; the source symlink is unchanged. Runtime locks are excluded; file content, directories and ordinary executable modes are retained. A pre-existing stale lock is preserved.

Create, verify and restore default to at most 10,000 archive members and 8 GiB of expanded file data, plus bounded TAR framing and metadata. The verifier checks those limits before hashing or restoring files; restore also checks available destination space before creating its target. For a known larger pier, pass `--max-members N --max-expanded-gib N` with appropriate positive limits to each command. A limit failure leaves the existing pier and archive untouched and does not publish a partial restore.

The `--ship` value labels the backup; it is not inferred by reading credential state. Confirm the selected pier and identity before stopping it. The manifest includes the original path, declared name, creation time and per-file hashes. The docked runtime is included; moving to another CPU architecture may require a suitable stock runtime on the destination.

After a routine backup, restart the original ship normally. **That restart means the archive is now historical; it must not later be treated as an interchangeable live clone.**

## Restore into an isolated new directory

```sh
python3 scripts/backup.py restore \
  --archive /private/backups/sampel-palnet-2026-10-14.tgz \
  --target /private/recovery/sampel-palnet-restored
```

The target must not already exist. All archive paths, entry types, sizes and hashes are checked before extraction. The extracted bytes are verified again before publication. The original pier is never overwritten or removed. **The restored pier stays stopped.** No networking, identity change, login, port binding or new ship is started by this command.

For an orderly migration, stop the source, create the final backup, keep the source stopped, restore on the destination, then start **only the destination**. Preserve the original stopped copy until recovery is accepted. Never run two copies of the same networked ship. If the source continued operating after the backup, or if the original ship was lost, consult the current Urbit recovery/reset procedure before reconnecting historical state to Ames; file integrity alone cannot establish network continuity. Do not automatically breach or reset an identity as part of this script. [Urbit runtime reference](https://docs.urbit.org/user-manual/running/vere).

For a functional rehearsal, use a dedicated fake-ship fixture with synthetic vault data, stop its source, restore to a separate owned directory, and boot the restored fixture on explicitly selected loopback ports. Do not use a real identity or expose a fake ship to the Internet. This is the appropriate place to demonstrate:

- The selected source was stopped and remains unchanged.
- The restored ship starts and serves the Urbitwarden and Connect desks.
- An official client can sign in, locally unlock the restored wrapped account key, and read a known synthetic login after sync.
- The original source and restored copy are not running together.

`test_backup.py` tests round-trip bytes/modes, lock exclusion, refusal of existing destinations and changed archive content. Those filesystem checks do not alone prove a native boot or official-client recovery; record that rehearsal separately with the source archive version and actual client version.

## Client exports

A verified official-client export is a useful additional vault-only recovery format, but does not replace a full ship backup. Use only an export mode demonstrated by the current client-support report. A plaintext client export contains readable passwords: keep it private and do not include it in evidence, source packages or Git. This is separate from authorization tokens, which cannot decrypt passwords. The backup utility never performs a client export or asks for a master password.

Official-client password/KDF/key-management and some purge/delete requests can also leave password-derived verification hashes in history and backups. This approved management payload boundary is separate from authorization tokens; see [account-management request history](known-limitations.md#account-management-request-history).
