# Known limitations and accepted scope

The [development policy](readiness-policy.md) removes synthetic/soak/trial qualification gates. Actual unsupported features and remaining technical controls are recorded separately in [the feature scope](vaultwarden-parity.md) and [resource controls](resource-controls.md).

## Retained authorization tokens cannot decrypt or read passwords

Owner decision, 2026-10-14: retaining authorization tokens in Urbit history is an accepted known limitation; these tokens cannot decrypt the vault or reveal passwords. It is not a blocker for making the Bitwarden desk usable. Eliminating this retention is not a release prerequisite. The separate token-derivation issues are fixed in the current source. This decision does not mark restricted journal validation complete.

The 2026-10-16 CLI sign-in correction adds one owner-authorized compatibility exception: its initial SSO access token lasts six minutes, outside the official CLI’s five-minute early-refresh window. Access tokens newly minted by refresh and all other clients retain the 60-second access lifetime. The original retention decision remains unchanged.

| Control | Current behavior retained |
|---|---|
| Initial CLI SSO access token | Six minutes |
| Other Bitwarden access tokens | 60 seconds, including newly minted CLI refresh responses |
| Connect authorization grant | 30-day absolute lifetime; refresh does not extend it |
| Identical refresh-response retry | Five-second grace, with native active-state cleanup |

During the existing five-second retry grace, an identical cached response can still contain the initial six-minute token. JWT expiration, server expiry and `expires_in` agree. Owner revocation remains authoritative during the initial token lifetime.

SSO separates vault decryption from backend authorization. In the supported SSO flow the master password and unwrapped vault keys stay in the client, while authorization codes, bearer/refresh tokens and owner cookies can enter event history. A still-valid copied token may authorize operations on encrypted vault data; it does not itself decrypt passwords. This is the usual stolen-token consequence, with the Urbit-specific retention surface described here. Owner authority has its own scope and is not limited to a Bitwarden token.

For ordinary Bitwarden HTTP routes, Vere constructs an event input containing the original request headers and body. Gall-side hashing, route rejection and cache expiry do not redact that original input. This does not mean that the disk write always occurs before Gall evaluation, or that every native HTTP path becomes an event. Read-only runtime scry/cache exceptions do not implement the full Bitwarden API. See [request construction](https://github.com/urbit/vere/blob/vere-v4.6/pkg/vere/io/http.c#L1518-L1540) and [completed-event persistence](https://github.com/urbit/vere/blob/vere-v4.6/pkg/vere/mars.c#L235-L250).

## Existing native history-retention tools

Stock Vere already provides `roll` to start a new event-log epoch and `chop` to remove epochs older than the newest two. These are existing runtime maintenance tools, require a stopped ship, and do not change application session lifetimes. They offer a practical way to reduce accumulated historical copies without a runtime patch or another service. See the [official roll and chop documentation](https://docs.urbit.org/user-manual/running/vere#chop).

This is history retention management, not a guarantee of secure erasure. Retained epochs, current snapshots/state, separate backups and filesystem snapshots are separate copies. `pack`/`meld` compact or deduplicate state rather than selectively removing journal credentials. Maintenance applies to the whole pier; the Bitwarden desk must not silently prune other apps' history. Any operator procedure needs its own explicit target, recovery boundary and verification. No journal maintenance was executed for this decision.

This native maintenance route remains a follow-up opportunity, not a prerequisite for the desk's usability work. Session lifetimes are not being shortened as a substitute. The initial CLI compatibility exception above is unrelated to retention maintenance.

## Separate outstanding work

The two token-derivation fixes were verified with an isolated synthetic ship. The restricted journal and credential-state checks remain deferred. This accepted limitation is unchanged. Unsupported client actions and unexercised clients remain labelled accurately in [client support](client-support.md); an unsupported operation is not evidence that its sensitive inputs were prevented before transmission.

The [scoped functional report](../evidence/remaining-native-hardening.md) records demonstrated behavior. Ordinary offline password guessing against copied ciphertext, client compromise and backend availability are not additional Urbit-specific defects.
