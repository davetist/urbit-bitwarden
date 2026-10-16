# Content capacity and operational controls

## Removed product quotas

The Bitwarden desk no longer rejects retained content because of any of these former ceilings:

- 1,000 ciphers, including trash, or 1,000 folders.
- 64 KiB per cipher or folder.
- 4 MiB aggregate cipher data or 1 MiB aggregate folder data.
- The derivative 65,558-byte / 4,216,304-byte delete/restore ceilings.
- Import item/folder counts and aggregate storage quotas.
- The desk’s 256 KiB ordinary-request and 6 MiB import-request byte ceilings, explicitly approved for removal by the owner.

The same rules apply to create, edit, import, trash and restore. Native transport/runtime limits and available memory still apply; removing the desk ceiling does not make a single HTTP request infinitely large. Imports still build an in-memory candidate and commit only after shape and folder-relationship validation succeeds. Revision conflicts still return 409. Stored data is bounded by the host and Urbit runtime's actual resources, not a declared unlimited-capacity guarantee. Sync currently returns the complete vault; pagination/streaming is separate implementation work.

## Remaining controls

- **Token exchange:** 32 outstanding exchanges, each expiring after 30 seconds. These bound held HTTP requests waiting on Connect, not the number of vault items or folders.
- **Authorization lifecycle:** six-minute initial CLI token, otherwise 60-second access tokens; 30-day absolute Connect grants; five-second identical-response retry. Replay rejection and owner revocation remain intact. The existing 4,096 consumed-refresh-digest boundary still requires new authorization rather than discarding replay history and accepting an old token.
- **Owner bootstrap:** eight active owner-cookie CSRF contexts, expiring after 30 minutes. This is separate from vault content capacity.
- **Operator tools:** configurable backup archive expansion/member guards, deployment-source bounds, canonical target/ownership checks, archive integrity and running-pier locks remain. They prevent malformed archives or incorrect deployment targets from silently damaging state; they do not cap the stored vault.

These controls are disclosed separately so removal of content quotas is not misrepresented as removal of every numeric protocol or operational bound. Old quota-only checks are retired, with their original source preserved under [history](history/removed-quota-checks/README.md). No synthetic or soak tests were run for the cleanup.
