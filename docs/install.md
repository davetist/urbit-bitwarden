# Install the Urbitwarden desk

The vault backend runs in Gall/Hoon; HTTPS terminates in stock Eyre/Vere. Python is a one-time local operator tool for source import and backup, not a running backend or service. No proxy, external identity service or runtime extension is required. Connect remains generic authorization software; the Urbitwarden desk owns the encrypted vault and Bitwarden protocol.

Use an existing ship you own, a backed-up pier, and an HTTPS hostname reachable by every intended client. Phones need a network-reachable hostname, not the desktop's `localhost`. The certificate must cover that hostname and be trusted by each client's normal trust store. This helper does not change DNS, firewall rules, listener ports or service supervisors. The checked runtime/kernel baseline is recorded in `toolchain.json`; this installer does not upgrade either one.

## Obtain the desks

The Urbitwarden desk uses the latest independently maintained [Connect desk](https://github.com/davetist/urbit-connect). There is no pinned Connect version or Git submodule. From a checkout of this repository, build a self-contained source package:

```sh
python3 scripts/package.py
```

The tooling obtains the latest Connect `main` sources under ignored `.work/dependencies/urbit-connect`. Set `URBIT_CONNECT_ROOT=/absolute/path/to/urbit-connect` to use a local development checkout instead. The archive includes the Urbitwarden desk at `desk/` and Connect at `dependencies/urbit-connect/desk/`, plus the operator tools and licenses needed for installation. Its manifest records which Connect source was packaged for provenance; that record is not a compatibility pin. Once built, deployment needs neither Git nor a running source checkout or external service. Rebuild the package to include later Connect updates.

## Select and inspect

Extract `dist/urbitwarden-source.tgz` into a new source directory. Check it against `dist/urbitwarden-source.tgz.sha256` from the build (or a trusted published checksum when downloading a package); the included manifest verifies the bytes to be imported, but does not establish the publisher's identity by itself. Run the helper as the pier's operating-system owner on the same host. The existing ship must be running with its stock `.urb/conn.sock` local control socket available. The pier directory itself must be a canonical path; its `.run` may be a regular executable or a symlink to the selected regular executable. The installer does not execute that binary or follow other pier-data symlinks.

```sh
python3 /path/to/source/scripts/deploy.py \
  --pier /absolute/path/to/your-pier \
  --ship '~sampel-palnet' \
  --origin https://ship.example \
  --source /path/to/source
```

Replace both example identity and paths with your exact selection. This default is a plan: it checks the live ship identity, the two desk names, route ownership, and every source file in the selected desks against `INTEGRATION-MANIFEST.json`. It does not import files or change certificates. The explicitly selected source directory may be a filesystem alias and is resolved once; paths inside its manifest and desks may not be symlinks. Missing, altered or unlisted desk source is refused. The source root is the extracted directory containing `INTEGRATION-MANIFEST.json`, independent of the current working directory or where this helper is launched. Source validation accepts at most a 1 MiB manifest with 4,096 entries, 4,096 desk paths, 256 desk files, 1 MiB per desk file and 8 MiB of desk file content in total; oversized input is rejected before import. No owner code, cookie or Bitwarden token is needed by the installer.

The installed desk appears as a **Urbitwarden** tile in Landscape. Its bundled shield image is served by the ship at `/apps/urbitwarden/vault/tile.png`, with the same ship-login requirement as the other UI assets. Clicking the tile opens the owner page. Existing installs receive the tile when updated with this desk source.

The owner page and **self-hosted server URL for official clients** are:

```text
https://ship.example/apps/urbitwarden
```

`--origin` is the origin only. The installer appends `/apps/urbitwarden`. The desk serves its UI and Bitwarden API beneath that prefix; it does not claim `/`, `/api` or `/identity`. Connect uses `/apps/connect` and `/connect`. The installer refuses another app's overlapping exact or child routes. The ship's home page and unrelated apps stay available.

## Install or update

After reviewing that selection, repeat the same command with `--apply`. Connect source is imported and installed first, followed by the Urbitwarden desk. The imports use the live selected ship identity, not a fake-ship name. They update the selected source files through Clay; they do not replace `%base` or delete unrelated files.

If either selected desk already exists, inspect it first and explicitly add `--update-existing`. That authorizes replacement of packaged files in those **two named desks only**. Preserve any local modifications separately before choosing it. Import is phased because Hoon marks must be available before non-Hoon desk metadata; it is not a transaction spanning both desks. A failed command can leave an incomplete import. Fix the reported source or native error and rerun the same verified release; do not reset a pier or delete application state as a retry technique.

The command reports successful control requests, not a substitute for an end-user acceptance check. After installation:

1. Open the displayed Urbitwarden URL with normal HTTPS validation, log in to the ship if requested, and complete the owner setup/enrollment there.
2. Confirm Connect is configured for the same exact HTTPS origin. Enrollment creates no client registrations. Each official client is registered under its `urbitwarden-` ID when its first valid SSO attempt reaches the authenticated owner browser. Owner authorization remains in Connect; the vault password is used locally to wrap/unlock the account key.
3. Configure an official client with the displayed server URL, choose single sign-on and follow the page's organization instructions.
4. Unlock locally, create one synthetic login, sync it to a second official client, then delete/restore it. Confirm the original ship home page still opens.

The session policy uses a six-minute initial CLI SSO access token and 60-second access tokens for subsequent newly minted CLI tokens and all other clients. The 30-day absolute grant lifetime and five-second retry grace remain unchanged. Application reloads may require an in-flight request to retry. The first upgrade from the vulnerable Bitwarden token format revokes existing Bitwarden sessions and requires a new SSO sign-in; encrypted account keys, ciphers and folders are preserved. Later reloads preserve current sessions and the five-second retry grace.

## Native HTTPS and renewal

Prefer the ship's existing valid Eyre certificate and its existing renewal arrangement. Stock Urbit includes `%acme`, which obtains and renews certificates natively. On a suitable networked planet/star, `|dns-config` guides the existing Urbit domain setup. A custom domain can be added to Eyre with the native `%turf` rule; Eyre notifies `%acme` of the requested domains. DNS must already point to the ship, and the CA's HTTP challenge must reach native Eyre on public port 80. These are explicit operator network choices, never actions performed by this installer. Keep those requirements working for renewal. Public certificate issuance still uses the ordinary certificate authority; no external vault or authorization service is introduced. The native implementation is in [Eyre](https://github.com/urbit/urbit/blob/master/pkg/arvo/sys/vane/eyre.hoon) and [ACME](https://github.com/urbit/urbit/blob/master/pkg/arvo/app/acme.hoon).

If you already have a PEM certificate chain and matching PEM private key, the installer can pass them directly to Eyre. It checks that the pair loads and requires a private key file with no group/other permissions. It does not display the key, put it in a command argument, or save another copy. This explicit command replaces Eyre's existing certificate, so use it only for the chosen ship and correct hostname:

```sh
python3 /path/to/source/scripts/deploy.py \
  --pier /absolute/path/to/your-pier \
  --ship '~sampel-palnet' \
  --origin https://ship.example \
  --tls-only --cert /private/path/fullchain.pem --key /private/path/privkey.pem \
  --apply --apply-tls
```

Omit `--apply --apply-tls` to inspect that certificate replacement plan. For manually supplied certificates, repeat the command with the renewed files before expiry; `--tls-only` does not reload either application. Manual PEM installation does not create an automatic renewal job. Use the ship's native `%acme` configuration when automatic native renewal is desired. Never bypass certificate validation in real clients. No certificate installation, public listener change or renewal was performed merely by adding this tooling.

## Known limitation, with precise scope

Urbit journal history may retain **access/refresh authorization tokens. These tokens cannot decrypt the vault or read its passwords.** A still-valid stolen token can authorize access to the encrypted vault, subject to its permissions; it is not the master password or unwrapped vault key. This is an accepted known limitation, not a deployment blocker. Session lifetimes remain unchanged. See [known limitations](known-limitations.md) and [backup/recovery](backup.md).

Official-client password/KDF/key-management and some purge/delete requests can also leave password-derived verification hashes in history and backups. This approved management payload boundary is separate from authorization tokens; see [account-management request history](known-limitations.md#account-management-request-history).

## Rename an existing Bitwarden desk

Do not install an empty `%urbitwarden` desk over an existing `%bitwarden` vault. Build and extract the current source package, then run `scripts/migrate_urbitwarden.py` with the same `--pier`, `--ship`, `--origin` and `--source` selection as above. Without `--apply` it verifies the target and prints a plan. Repeat with `--apply` to migrate.

The helper suspends the old writer, loads its saved encrypted account/content and sessions into `%urbitwarden`, and migrates only Connect registrations whose resource agent is `%bitwarden`. Client IDs become `urbitwarden-*`; namespaces, enabled/disabled choices and grants stay intact. Official client wire IDs and `bitwarden://sso-callback` remain unchanged. Temporary migration source is replaced with production source after the in-ship comparisons pass; Connect's production source is restored byte for byte. The old desk stays suspended with its saved state for rollback and is never nuked.

The canonical URL is `/apps/urbitwarden`. `/apps/bitwarden` remains a compatibility route for already-configured official clients; new setup pages and the Landscape tile use Urbitwarden. The browser extension's old callback remains allowed alongside the new one. The backup manifest filename stays unchanged so existing backups remain readable. Dated evidence and source-history paths retain their historical names.

If migration stops, do not enroll an empty replacement vault. Preserve both desks and the original Connect source, inspect the reported stage, and recover before allowing further writes. Confirm the vault summary, Connect registration/grants, and an actual client sync before retiring the old desk.
