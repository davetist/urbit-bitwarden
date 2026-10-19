# Personal vault implementation plan

**Goal:** Implement the agreed personal-vault content and management scope through official clients, with Connect as the sole authorization authority.
**Architecture:** Keep the Urbitwarden agent responsible for encrypted vault state and Bitwarden wire contracts. Extend its versioned state with encrypted attachment octets; retain generic Connect unchanged unless a concrete generic dependency requires a fix. Use separate pure helpers for attachment wire parsing.
**Spec:** [Agreed scope](vaultwarden-parity.md).

## Constraints

No synthetic, unit, fixture, integration or soak workloads. Use source-contract review, compilation, static asset inspection and deterministic packaging. Official-client interaction requires an identified authorized setup. No password/API-key/OTP/backend-passkey login, shared vaults, Sends, breach service or full web vault. No artificial content quotas. Preserve atomicity, revision conflicts, grant expiry/revocation, existing data and client-held encryption keys.

## Work

- [x] Implement all eight cipher wire types, protected metadata, partial updates, bulk move/trash/restore/permanent delete and archive/unarchive routes. Reject cross-vault ownership and invalid folder references; validate the complete bulk request before committing.
- [x] Implement native encrypted attachment metadata, exact-byte multipart upload, Connect-bound temporary downloads, deletion and wrapped attachment-key updates. Migrate old vault state without losing data. Preserve binary lengths and embedded/trailing zero bytes.
- [x] Implement personal equivalent-domain settings, appropriate premium/client capability flags and icon route compatibility without introducing an external service dependency. Keep ordinary sync/revisions and encrypted import/export contracts.
- [x] Resolve official-client password/KDF/key-rotation and purge/delete payload contracts against the client-held-secret boundary. These clients may transmit password-derived authentication hashes; do not silently adopt that custody change. The owner approved including these operations after disclosure on 2026-10-17; implement them using Connect authorization and no stored password verifier.
- [x] Add the ship-page vault summary and official-client instructions; keep plaintext content and keys out of it. Document optional trash retention and current client capability boundaries.
- [x] Review source and migration/error paths, compile available artifacts, inspect changed UI and package deterministically. Record actual verification without claiming unperformed client workflows. Commit scoped changes and verify both repositories are clean.

## Review focus

Concurrent stale edits; missing/duplicate IDs in bulk changes; interrupted or size-mismatched attachment upload; revoked/expired download authority; account key changes preserving every cipher/folder/attachment atomically. Source review and compilation replace synthetic tests under the owner's explicit instruction.
