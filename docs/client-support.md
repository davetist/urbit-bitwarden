# Official-client support and journal boundary

The Bitwarden desk is an Urbit-native personal-vault backend. Connect owns generic authorization; the Bitwarden desk owns encrypted vault storage and Bitwarden protocol behavior. Stock Vere/Gall/Eyre serve the backend. Client executables are unmodified.

## Pinned clients

The exercised clients are official CLI **2026.9.1** and Chrome extension **2026.9.3**, identified by `artifacts.json` and the existing upstream-file verification. Other versions, desktop and mobile are not qualified by these results.

The supported workflow is browser enrollment of a fresh account, Enterprise SSO (`urbit-vault`), local unlock, personal login items, explicit synchronization and trash/restore. The fixture's synthetic secrets and client profiles remain private development data.

| Action | Current support/evidence | Transmission assurance |
|---|---|---|
| Enterprise SSO | CLI and extension complete native Connect consent | Prior SSO audit exists; not rerun in this hardening change |
| Local unlock | CLI and extension decrypt the enrolled vault | Existing client-side path; no new request/journal inspection |
| Personal item create/edit/sync | CLI creation, extension edit and CLI readback exercised | Client encryption preserved; expanded secret-transmission validation deferred |
| Trash/restore | Native lifecycle/capacity tests, official CLI and extension exercised | Ordinary functional verification only |
| Lock and local re-unlock | Official CLI exercised | No new secret-transmission inspection |
| Ordinary password sign-in | Server rejects prelogin with `sso_required`; prior CLI rejection evidence retained | Fresh pre-transmission verification deferred |
| Master-password re-prompt | Do not assume every prompt uses the server; not qualified by this run | Action-specific tracing/validation deferred |
| Export | Not qualified by this run | Action-specific tracing/validation deferred; UI visibility is not support proof |
| Password change, account deletion, account recovery | Unsupported by the desk | A late server error cannot establish that no sensitive request was sent |
| API keys, organizations, attachments, Sends, passkeys, notifications/push | Outside this personal-vault preview | No compatibility or journal guarantee |

The stock extension displays a 30-day bin-expiry message. Automatic 30-day trash purging is not implemented by this preview; explicit restore and permanent deletion are the supported lifecycle operations.

## What native cache cleanup guarantees

The existing five-second refresh-response cache remains durable to preserve identical retry responses across a quick restart. Each response schedules a native Behn expiry. When that wake is processed, the agent deletes the matching expired response; an older wake cannot delete a replacement. Reload removes expired/orphaned entries and re-arms valid ones. The current refresh credential and authorized session survive ordinary cache expiry.

This is active-state cleanup. A stopped or stalled runtime cannot process a timer, and previously written snapshots/events may still contain credentials. The request path continues to enforce expiry before returning a cached response even if timer delivery is delayed.

## Journal limitation — accepted

The owner accepts journal credential retention as a known limitation, not a usability blocker. Keep the existing 60-second access lifetime, 30-day absolute Connect grant and five-second retry grace. See [the recorded decision and native retention tools](known-limitations.md).

Ordinary Bitwarden HTTP requests become event inputs whose original headers and bodies are retained in history. A Gall route rejection, application allowlist or cache deletion does not redact that original input. This statement concerns the persisted input, not a claim that the disk write precedes Gall evaluation. No new server capability flags were guessed or enabled to claim prevention.

An action can be labelled **prevented before transmission** only after the pinned official client is shown to avoid sending the sensitive material. No additional action received that label in this change: expanded client-action and journal security validation were explicitly deferred by the user. If a required official action has no compatible pre-transmission control, it remains an unresolved constraint, not a successful fix.

## Verification commands

Use the owned review fixture and its matching enrollment/client profiles. Do not run parallel CLI processes against the same CLI profile.

```sh
CONNECT_BW_FIXTURE=review-fixes python3 integrations/bitwarden/scripts/test_fixture.py
CONNECT_BW_FIXTURE=review-fixes python3 integrations/bitwarden/scripts/test_start_ports.py
CONNECT_BW_FIXTURE=review-fixes python3 integrations/bitwarden/scripts/test_token_cache.py
CONNECT_BW_FIXTURE=review-fixes python3 integrations/bitwarden/scripts/test_refresh_compat.py
CONNECT_BW_FIXTURE=review-fixes python3 integrations/bitwarden/scripts/test_functional_lifecycle.py
CONNECT_BW_FIXTURE=review-fixes python3 integrations/bitwarden/scripts/test_soft_delete_bound.py
CONNECT_BW_FIXTURE=review-fixes python3 integrations/bitwarden/scripts/test_official_lifecycle.py
CONNECT_BW_FIXTURE=review-fixes node integrations/bitwarden/scripts/browser.mjs --functional-only
```

The browser's functional-only mode uses an already-enrolled fixture and disables request/key capture. The default audit harness remains available and unchanged in its assertions, but its selected-fixture routing is corrected. The mixed authorization/replay suites and journal audit must not be described as passing this change until separately run after the restriction is lifted.

The two previously identified token-derivation issues remain assigned to separate work and are unchanged here. This document does not qualify the prototype for production use.
