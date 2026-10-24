# Focused desk security review — 2026-10-24

Source: `7f9773cb276fd2dabe1d766a0322dfaa90346060`. A completed offline Codex Security Standard scan reviewed all 35 tracked `desk/` files, focusing on Connect-backed authorization, encrypted attachment access, password/KDF/key management, and local recovery entry points. It reported no vulnerability under the documented single-owner ship trust model. The scan did not run a live attack replay; client and recovery behavior has separate evidence in this directory.

Four source-backed candidates were investigated and rejected as cross-boundary findings:

- Account password/KDF changes require a live bearer plus Connect grant. The desk deliberately does not retain or compare a password verifier; a stolen approved token can still cause lockout by changing wrapped material.
- Attachment preparation and upload have no desk quota by policy. An approved client can exhaust ship resources; multipart format, declared length, session and grant checks remain enforced.
- Any same-ship agent can invoke restore into a completely empty vault. Same-ship agents are inside the current trust boundary; this cannot overwrite an enrolled vault. Reassess if hostile local desks become an explicit threat.
- The local backup scry returns a portable encrypted snapshot. HTTP scry requires the owner session, and local Gall code can already scry the agent's saved state. Protect owner cookies and exported archives.

These are scope and residual-risk statements, not claims that arbitrary clients are safe or that Urbit history is erased. The accepted history-retention limits remain in [known limitations](../../docs/known-limitations.md).
