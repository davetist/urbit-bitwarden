# Bitwarden native SSO implementation plan

> Historical plan, retained from the original Connect checkout. Its original paths and terminology describe that implementation period, not the current repository layout or execution authorization. The backend is the native Bitwarden desk. See [the repository split record](../../repository-split.md) for current paths, latest-Connect dependency handling and verification boundaries.

Goal: demonstrate owner-approved Connect SSO and local key unlock with unmodified CLI 2026.9.1 and Chrome extension 2026.9.3 on a fresh stock-Vere fixture.

Architecture: a reusable opt-in resource interface in Connect shares its existing authorization records, consent, code exchange and owner revocation. A separate Bitwarden adapter owns its wire compatibility. Separate Bitwarden state stores encrypted account envelopes and vault records. A bounded refresh retry cache is valid only while its Connect session remains live. Generic document clients retain their protocol and refresh semantics. Browser WebCrypto enrollment sends only encrypted envelopes and public metadata. Backend remains Hoon/Gall/Eyre.

The initiating task message is the acceptance specification. No commits, real ships, old fixture writes, external auth servers, runtime patches or global TLS trust changes are authorized. Existing alpha qualification remains separate. Work is executed inline; this source directory has no Git metadata. Baseline desk saved in `.work/bitwarden-sso/baseline-desk`.

- [x] Fresh loopback fixture, local Eyre TLS, reproducible installer and baseline tests.
- [x] Opt-in client/scopes/callback policy; negative regression tests; preserve generic document authority.
- [x] SSO entry and identity endpoints; shared owner approval and code exchange; JWT/envelopes; session-bound CRUD.
- [x] Refresh race/replay/revocation/restart tests, including old-token revocation during grace.
- [x] Browser-only cryptographic enrollment; lifecycle fallback audit and traffic/history checks.
- [x] Official CLI and extension login/unlock and cross-client CRUD, restart and revocation with screenshots.
- [x] Existing applicable regressions, source diff review, setup/protocol/security docs and reproducible evidence.

Review focus: exact loopback port/path matching; adapter tokens must never acquire document scopes; stale refresh cache must never resurrect revoked sessions; malformed enrollment must not replace account keys; reject automatic password fallback before clients send hashes wherever their protocol supports it. Unsupported lifecycle actions remain explicitly excluded from the no-hash workflow claim.

## Superseding scope correction

Connect changes are reusable only. Bitwarden is a separate Gall adapter under `integrations/bitwarden/desk`; no Bitwarden IDs, port ranges, scopes, token claims or key envelopes enter generic code. Owner client registration optionally supplies an immutable integration policy: local Gall resource agent, permitted scopes, and up to eight exact redirect URIs. HTTP loopback is permitted only in that explicit policy; ordinary clients retain the existing redirect rules. Resource scopes cannot include Connect document scopes.

The resource agent exchanges a code through a local Gall request authenticated by kernel provenance (`src` and `sap`). Connect returns a session grant to that same registered agent. A read-only scry verifies the live session, policy, client enablement, absolute expiry and namespace epoch. The adapter owns JWT and refresh concurrency but checks Connect authority on every operation. Generic HTTP token exchange cannot exchange a resource-bound code. No claim of OIDC conformance is made.

A separate `grant-probe` notes consumer exercises the same interface, including exact localhost callback and resource isolation. Existing document clients stay compatible. Gall state migrates from version 1 to version 2 by appending the integration policy map; existing durable values and session behavior are preserved.

Final evidence: integrations/bitwarden/evidence/report.md. 74 Hoon, 43 live HTTP, 19 web codec, 68 Swift SDK, 2 public consumer and 61 tooling tests passed; synthetic journal scan covered 5,462 events without known-secret matches. Release qualification and unsupported lifecycle limits remain explicit.
