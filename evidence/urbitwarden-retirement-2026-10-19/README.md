# Old desk retirement — 2026-10-19

The owner explicitly authorized removing the old `%bitwarden` desk and its runtime compatibility support after the Urbitwarden migration.

- Confirmed the old and new encrypted account/content fingerprints matched before retirement. Compared the active vault content and Connect registration/policy fingerprints around the update and cleanup; equality checks passed.
- Deployed canonical-only routing and browser callbacks to `%urbitwarden`. The old `/apps/bitwarden` route was disconnected by its owning duct. Both the old API configuration endpoint and browser callback returned HTTP 404.
- Uninstalled the old desk and nuked only its single `%bitwarden` Gall agent. Its nonce/state entry is absent. Removed all 31 app/source files; Clay requires the remaining `/sys/kelvin` metadata file and retains the historical desk name/revisions. No executable app, tile, route or vault state remains active under the old name.
- The enrolled vault retained one item, the same revision and no folders/attachments/trash. The desktop Connect registration retained its namespace, enabled state, scopes and native callbacks. Both current vault sessions had live Connect grants. Connect's owner bootstrap and Urbitwarden's owner page/configuration returned HTTP 200.
- The production agent and updated one-time migration hooks compiled on Vere 4.6 / Zuse 408. Source consistency, Python/JavaScript syntax, documentation links and deterministic packaging passed. No synthetic or soak workloads ran.
- A new official desktop sync after compatibility removal could not be checked because Computer Use reported the Mac locked. The successful desktop sync in the earlier migration record predates this removal.
