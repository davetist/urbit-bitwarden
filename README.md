# Urbit-native Bitwarden desk — synthetic-data preview

This native Bitwarden Gall desk translates the official Bitwarden CLI and Chrome extension's Enterprise SSO wire protocol to Connect's reusable local-resource authorization. Stock Vere 4.6, Gall, Hoon and native Eyre HTTPS serve every production request. Python/Node scripts are development and verification tools only; no auth backend, reverse proxy, Bitwarden server library, Vaultwarden code or runtime fork is required.

Connect owns registration, PKCE authorization codes, ship-owner consent and live grant revocation. The Bitwarden desk owns the `cli`/`browser` IDs, `api offline_access` scope, JWT claims, encrypted vault API and bounded refresh retry. See [the generic contract](../../docs/resource-integrations.md).

Current scoped changes and verification: [remaining native hardening](evidence/remaining-native-hardening.md). Exact client/action support and deferred journal checks: [client support](docs/client-support.md). The two separately assigned token-derivation repairs remain pending. Journal credential retention is an [accepted known limitation](docs/known-limitations.md), not a usability blocker; the current session lifetimes are retained.

## Supported workflow

Enroll a fresh synthetic account on the ship's `/` page while logged in as owner. WebCrypto derives the local password key and encrypts a randomly generated user key and RSA private key before sending their envelopes. Choose Enterprise SSO in Bitwarden, enter organization `urbit-vault`, approve on the ship, then unlock locally with the enrollment password. The official clients encrypt/decrypt vault items. CLI creation, extension decryption/editing, CLI readback/deletion, native restart persistence and Connect revocation are acceptance targets; see [evidence](evidence/report.md) for executed results.

One fresh personal account, login items and explicit sync are supported. This is not a production vault or a full Bitwarden server. Organizations, attachments, Sends, notifications/push, passkeys, password changes, account deletion, API keys and password-verification actions are unsupported. Do not import real secrets. Existing Bitwarden accounts cannot simply point here: account keys must match the local password and this enrollment.

Ordinary password sign-in is rejected at prelogin, before the tested official CLI derives/sends an authentication hash. An arbitrary or future client can still send sensitive input to any HTTP route; rejecting that input inside Gall cannot remove it from Urbit's event journal. Unsupported lifecycle actions may send password-derived material before rejection. Use only the exercised SSO and local-unlock flow.

## Reproduce on Apple Silicon macOS

Prerequisites: Python 3.10+, Node 22.12+, npm, OpenSSL, the repository's pinned stock Vere and pill (`toolchain.json`). `web/node_modules/playwright` and Chrome for Testing 151.0.7922.34 are needed for the browser harness. Setup pins browser installation through Playwright 1.62.1 (revision 1234), independently of the newer web-test package. Client downloads are pinned in `artifacts.json`; no account or paid service is needed. The dedicated fixture lives exclusively under `.work/bitwarden-sso`, with loopback ports HTTP 19680, native HTTPS 19681 and Ames 19682. Keep this directory private: it contains synthetic credentials, cookies, tokens, keys, client profiles and journal data.

```sh
python3 integrations/bitwarden/scripts/setup.py
node integrations/bitwarden/scripts/browser.mjs --enroll
```

Setup refuses occupied ports for a new fixture and never reuses other piers. The fixture certificate is trusted only by the test CLI via `NODE_EXTRA_CA_CERTS` and by the isolated browser via its exact SPKI pin; no global trust change. If Chrome disables the unpacked official release, enable Developer mode in this isolated profile at `chrome://extensions`. The harness preserves official extension files byte-for-byte. Set `BW_BROWSER_EXECUTABLE` only if the Playwright browser path is unavailable.

The harness prints a private stdio control interface; it opens no debugging TCP port. Start official CLI SSO from a PTY using `python3 integrations/bitwarden/scripts/cli_sso.py`, then open the captured URL from private `cli-browser-url.json` in that same owner-authenticated browser. The PATH-only browser-opener shim captures the official URL; it does not alter client code or protocol. Approve the real UI. The CLI uses its own loopback callback listener. Extension settings should use self-hosted `https://localhost:19681`, SSO organization `urbit-vault`, and the same email. Its official connector returns the code/state with the upstream postMessage contract.

After enrollment, scripts `cli_ops.py create`, `read` and `delete` use the official CLI; the password is passed only to local `unlock --passwordenv`, never in argv. `test_generic.py` expects the unrelated `notes-native` registration created by `test_policy.py`. The live adapter, hardening, pending, restart, resource-revoke and official-negative scripts use only this fixture. `test_connect_regressions.py` removes its registrations and revokes all previous test sessions; run it last, after client acceptance. It substitutes fixture paths/control in the existing Connect HTTP tests without changing their assertions.

Stop the owned fixture with `python3 integrations/bitwarden/scripts/stop.py`. No script deletes the evidence or other fixtures.

## Boundaries and recovery

Access tokens expire after 60 seconds; Connect's 30-day absolute grant lifetime remains authoritative and is not extended by refresh. JWT signatures are native Hoon HMAC-SHA256, but API acceptance also requires exact token-digest membership and a live Connect grant. Refreshes rotate once, with a five-second cache returning the same response to overlapping official-client retries. Native Behn timers expire those responses during idle operation; reload prunes expired entries and re-arms valid ones. Historical journal/snapshot copies are not erased. A consumed predecessor used after grace revokes both Bitwarden and Connect sessions. Each Bitwarden session family retains at most 4,096 consumed refresh digests; reaching that limit requires a new SSO authorization. Owner revocation is checked before the retry cache. Logout using a current or consumed refresh token deletes the family and releases its Connect grant. The ordinary Connect document-client refresh policy is unchanged.

Pending code exchanges are limited to 32 and time out after 30 seconds with HTTP 503. Reload completes held HTTP requests with 503. Late successful exchanges are revoked instead of becoming orphan grants. Enrollment can resume after partial registration failure; it reuses only matching enabled policies and refuses to overwrite conflicting clients.

Requests are limited to 256 KiB, serialized ciphers to 64 KiB, vault ciphers to 1,000 (including soft deletes), and aggregate serialized cipher data to 4 MiB. Hard deletion releases capacity. Stale revision writes return 409. This preview does not implement pagination for sync or a broad Bitwarden data model.

Revocation prevents further server access; it cannot erase plaintext or encrypted data already cached by a client. Local unlock may remain possible after revocation. The ship retains ciphertext, wrapped user/private keys, account email, metadata, owner cookies, authorization codes and bearer/refresh tokens in its event history. The synthetic journal audit checks specific known password/hash/key values across raw LMDB and decoded input events separately from active Gall state. It is evidence for tested flows, not a proof that no conceivable encoding or unsupported action can journal a secret.

## Reproduce the security evidence

Run `python3 integrations/bitwarden/scripts/audit.py` after browser enrollment and exercised client workflows, while the fixture is running and its `cli` registration still exists. The runner creates an isolated Python venv, installs pinned **lmdb 1.7.5** (read-only audit tooling, not server code), obtains a fresh probe token, exports both active Gall states through the stock local control socket without rendering their contents, verifies a native JWT against Python HMAC, and scans the raw LMDB plus decoded input events. Its prerequisites are the private files produced by setup and `browser.mjs --enroll`; the browser harness saves request traffic after each UI operation. Evidence is written to `evidence/history-audit.json`. All three positive controls—encrypted key envelope, owner cookie and issued access token—must appear in decoded events. No secret value is written to public evidence.

The separate `test_connect_regressions.py` intentionally removes the adapter registrations. Run the audit first, or restore the exact registration policies before auditing afterward. Private logs and piers are excluded from source packaging.
