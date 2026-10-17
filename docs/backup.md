# Back up and restore the native Bitwarden desk

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
- The restored ship starts and serves the Bitwarden and Connect desks.
- An official client can sign in, locally unlock the restored wrapped account key, and read a known synthetic login after sync.
- The original source and restored copy are not running together.

`test_backup.py` tests round-trip bytes/modes, lock exclusion, refusal of existing destinations and changed archive content. Those filesystem checks do not alone prove a native boot or official-client recovery; record that rehearsal separately with the source archive version and actual client version.

## Client exports

A verified official-client export is a useful additional vault-only recovery format, but does not replace a full ship backup. Use only an export mode demonstrated by the current client-support report. A plaintext client export contains readable passwords: keep it private and do not include it in evidence, source packages or Git. This is separate from authorization tokens, which cannot decrypt passwords. The backup utility never performs a client export or asks for a master password.

Official-client password/KDF/key-management and some purge/delete requests can also leave password-derived verification hashes in history and backups. This approved management payload boundary is separate from authorization tokens; see [account-management request history](known-limitations.md#account-management-request-history).
