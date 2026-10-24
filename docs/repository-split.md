# Repository separation

The Urbitwarden backend lives in [urbit-bitwarden](https://github.com/davetist/urbit-bitwarden). [urbit-connect](https://github.com/davetist/urbit-connect) retains reusable authorization, owner consent, local-resource grants, exact registered callback handling, document APIs, SDKs and its unrelated `grant-probe` consumer. Connect does not own the Bitwarden vault, client IDs, protocol behavior or release tooling.

## Source history and layout

The source boundary is Connect commit [`510d02870b7edeac598c039314e70745d3c569aa`](https://github.com/davetist/urbit-connect/commit/510d02870b7edeac598c039314e70745d3c569aa). Extracted subtree history ending at `528c1b6` preserves the history of its `integrations/bitwarden/` files. The published Connect history is preserved; removal happens in a later commit.

| Previous location in Connect | Location here |
|---|---|
| `integrations/bitwarden/desk/` | `desk/` |
| `integrations/bitwarden/web/` | `web/` |
| `integrations/bitwarden/scripts/` | `scripts/` |
| `integrations/bitwarden/docs/` | `docs/` |
| `integrations/bitwarden/evidence/` | `evidence/` |
| `integrations/bitwarden/artifacts.json` | `artifacts.json` |
| `tests/tooling/test_bitwarden_tooling.py` | `tests/tooling/test_bitwarden_tooling.py` |
| `docs/superpowers/plans/2026-10-14-bitwarden-*.md` | `docs/superpowers/plans/2026-10-14-bitwarden-*.md` |

The split preserves the native Bitwarden desk and browser setup source; tooling changes resolve their new paths and the separate Connect dependency. It does not change SSO, encrypted-vault behavior, official-client contracts or the session policy: 60-second access tokens, 30-day absolute Connect grants and five-second retry grace.

## Latest Connect dependency

Urbitwarden targets the latest Connect desk installed on the same ship. There is no submodule, vendored Connect source tree or compatibility pin in this repository. Development/setup tooling obtains the latest Connect `main` under ignored `.work/dependencies/urbit-connect`. `URBIT_CONNECT_ROOT` selects an existing checkout for local development.

Source packages include the selected Connect desk and record its source commit for reproducibility. That identifies the bytes in that package; it does not require future Urbitwarden installations to remain on that Connect commit. Packaging is a local preparation step. The deployed backend remains native Gall/Hoon/Eyre and requires no external authorization service.

## Evidence and private fixtures

The evidence files and screenshots preserve the historical observations; source commit IDs reflect the rewritten public Git history. The separate [2026-10-16 acceptance record](../evidence/current-2026-10-16/assessment.md) tests the split repositories together. Their original absolute paths, monorepo commands, source hashes and source locations describe the earlier run. Read an old `integrations/bitwarden/` prefix as this repository root when locating the corresponding current file. Links within historical reports that point outside that former subtree should be resolved against [the original Connect source](https://github.com/davetist/urbit-connect/tree/510d02870b7edeac598c039314e70745d3c569aa). Current commands are in the [README](../README.md), [installation guide](install.md) and [client support](client-support.md).

Private piers, credentials, client profiles, downloads and build products were intentionally left in the original checkout, outside Git. They are not silently adopted or rebound by this split. Fresh setup creates an owned fixture beneath this repository's `.work/`; any separate migration of an existing fixture must preserve its ownership and stopped-copy boundary.

The split is not new security validation. The subsequent token fixes are now present in both tested repositories; restricted credential-state, journal and adversarial checks remain deferred. Historical authorization-token retention remains an accepted limitation: those tokens cannot decrypt the vault or read passwords. Historical client/platform observations remain in [client support](client-support.md); they are not mandatory qualification gates.

## Separation checks

The [split verification record](../evidence/repository-split.json) records 59 passing offline checks across both projects, preservation of all 134 original Bitwarden subtree files, and byte identity of the native desk, browser setup source and historical evidence. The standalone source archive installed both desks on a fresh disposable fake ship; native HTTPS discovery, configuration, both owner pages and the Bitwarden page's actual JavaScript/CSS routes passed. The normal dependency helper also fetched the latest published generic Connect `main` without a sibling checkout override. Official applications were not rerun during the split itself. They were subsequently rerun on 2026-10-16 against both current standalone desks; see the acceptance record above.
