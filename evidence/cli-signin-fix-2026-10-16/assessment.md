# CLI first-attempt sign-in correction — 2026-10-16

The initial CLI token now lasts six minutes. This places it outside the unmodified official CLI’s five-minute early-refresh window while its refresh credential is being persisted. Every newly minted subsequent CLI access token and all other clients’ access tokens retain 60 seconds. JWT expiration, server expiry and `expires_in` use the same duration. The 30-day absolute Connect grant, five-second identical-response retry cache and owner revocation are unchanged; a cached initial response can still contain its original six-minute token.

The correction is confined to `++issue` in the Bitwarden agent. Initial issuance is selected from the stored `cli` client and the existing zero refresh-digest sentinel. No state migration, client patch, sign-in retry wrapper or Connect authentication change is involved. The user authorized this exception after the earlier pending-policy assessment.

The same unmodified official CLI 2026.9.1 previously failed once in eight new profiles. With this correction, **16 of 16 new profiles passed on their first browser-approved SSO attempt**, without retries or pre-existing authenticated profiles. This is observed acceptance, not a statistical guarantee against every possible startup failure. The original source analysis supports the access-before-refresh persistence race; the exact concurrent caller remains unproven. [Before](../signin-consent-followup-2026-10-16/baseline-results.json), [after](first-attempt-results.json).

Fresh live verification also passed:

- Native issuance contract: initial CLI lifetime 360 seconds; other clients and newly minted CLI tokens 60 seconds; identical initial retry response; real server-side 60-second expiry; rotation replaces the old bearer; owner revocation denies access and refresh.
- Full real-time initial-token expiry: access succeeds immediately before the six-minute deadline, fails after it, and normal refresh recovers with a 60-second token.
- Nine native Hoon cache lifecycle cases, plus six concurrent legitimate refresh retries, idle cache expiry and native restart compatibility.
- Official CLI local unlock, sync, encrypted create/trash/restore/read, lock/re-unlock, all four personal item types, folder create/rename/delete, filtered synthetic export and official import with new IDs and restored folder relationships. Task records and temporary plaintext export were cleaned up.
- Official CLI sync is denied after Connect owner revocation. Pinned official-client and stock-runtime file hashes were checked again.
- Ten offline tooling and three repository-layout cases passed. The source archive was rebuilt deterministically with the current Connect desk.

Run the focused native checks on an owned, enrolled review fixture with `CONNECT_BW_FIXTURE=review-fixes`, `URBIT_CONNECT_ROOT` pointing to the separate Connect checkout, and `python3 scripts/test_initial_cli_token.py` followed by `python3 scripts/test_initial_cli_expiry.py`. The latter waits through the actual six-minute deadline. The existing adapter suite’s expiry case now rotates to a 60-second token before its original access/code-expiry assertions; its separate restricted adversarial cases were not run in this functional follow-up. No credential-state or journal inspection was performed.

The [default-scale iOS consent fix](https://github.com/davetist/urbit-connect/blob/main/docs/consent-layout.md) and its official-source iOS Simulator validation remain valid: Connect executable sources are unchanged from that passing 362-case run. This follow-up changes its readiness documentation only. No additional App Store, physical-device, Android or production-readiness claim is made. The paired desks remain a single-account synthetic-data preview with the independent qualification gates recorded in the earlier assessment.
