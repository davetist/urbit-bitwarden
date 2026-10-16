# Historical fixture workflows

Preserved for source history only. Synthetic, soak and elapsed-time qualification workflows are not current readiness requirements and are not authorized by the 2026-10-16 cleanup request.

## Reproduce on Apple Silicon macOS

Prerequisites: Git, Python 3.10+, Node 22.12+, npm, OpenSSL, the repository's pinned stock Vere and pill (`toolchain.json`). `node_modules/playwright` and Chrome for Testing 151.0.7922.34 are needed for the browser harness. Setup pins browser installation through Playwright 1.62.1 (revision 1234), independently of the newer web-test package. Client downloads are pinned in `artifacts.json`; no account or paid service is needed. The dedicated fixture lives exclusively under `.work/bitwarden-sso`, with loopback ports HTTP 19680, native HTTPS 19681 and Ames 19682. Keep this directory private: it contains synthetic credentials, cookies, tokens, keys, client profiles and journal data.

```sh
npm ci
python3 scripts/setup.py
node scripts/browser.mjs --enroll
```

Run these commands from this repository root. Setup obtains the latest Connect source from `main` into ignored `.work/dependencies/urbit-connect`; set `URBIT_CONNECT_ROOT` to an existing Connect checkout when developing both desks locally. This source checkout supports installation and generic regression tests; production requests remain entirely within the installed Urbit desks.

Setup refuses occupied ports for a new fixture and never reuses other piers. The fixture certificate is trusted only by the test CLI via `NODE_EXTRA_CA_CERTS` and by the isolated browser via its exact SPKI pin; no global trust change. If Chrome disables the unpacked official release, enable Developer mode in this isolated profile at `chrome://extensions`. The harness preserves official extension files byte-for-byte. Set `BW_BROWSER_EXECUTABLE` only if the Playwright browser path is unavailable.

The harness prints a private stdio control interface; it opens no debugging TCP port. Start official CLI SSO from a PTY using `python3 scripts/cli_sso.py`, then open the captured URL from private `cli-browser-url.json` in that same owner-authenticated browser. The PATH-only browser-opener shim captures the official URL; it does not alter client code or protocol. Approve the real UI. The CLI uses its own loopback callback listener. Extension settings should use self-hosted `https://localhost:19681/apps/bitwarden`, SSO organization `urbit-vault`, and the same email. Its official connector returns the code/state with the upstream postMessage contract.

After enrollment, scripts `cli_ops.py create`, `read` and `delete` use the official CLI; the password is passed only to local `unlock --passwordenv`, never in argv. `test_generic.py` expects the unrelated `notes-native` registration created by `test_policy.py`. Existing protocol, hardening, pending, restart, resource-revoke and official-negative scripts use the selected fixture. Mixed security suites remain deferred during the current usability work. `test_connect_regressions.py` removes its registrations and revokes all previous test sessions; run it last, after client acceptance. It substitutes fixture paths/control in the selected Connect checkout's HTTP tests without changing their assertions. Those regression helpers are development dependencies, not part of the running Bitwarden backend.

Stop the owned fixture with `python3 scripts/stop.py`. No script deletes the evidence or other fixtures.
