# Historical security-audit procedure

Archived from the earlier README. This is not a current readiness requirement or authorization to run synthetic or journal checks. No such checks were executed for quota/gate removal.

## Historical security evidence — deferred during this work

The following is the existing audit procedure, not a check executed or authorized by the current usability work. Run it only when the separate validation restriction is lifted.

Run `python3 scripts/audit.py` after browser enrollment and exercised client workflows, while the fixture is running and its `cli` registration still exists. The runner creates an isolated Python venv, installs pinned **lmdb 1.7.5** (read-only audit tooling, not server code), obtains a fresh probe token, exports both active Gall states through the stock local control socket without rendering their contents, verifies a native JWT against Python HMAC, and scans the raw LMDB plus decoded input events. Its prerequisites are the private files produced by setup and `browser.mjs --enroll`; the browser harness saves request traffic after each UI operation. Evidence is written to `evidence/history-audit.json`. All three positive controls—encrypted key envelope, owner cookie and issued access token—must appear in decoded events. No secret value is written to public evidence.

The separate `test_connect_regressions.py` intentionally removes the Bitwarden client registrations. Run the audit first, or restore the exact registration policies before auditing afterward. Private logs and piers are excluded from source packaging.

The [current usability verification](../../evidence/current-2026-10-16/assessment.md) records actual clients, automatic-sync boundaries, recovery and cleanup.
