# Personal-vault implementation build — 2026-10-17

This record concerns source compilation and packaging. No synthetic, unit, integration, fixture or soak tests, ship boot, deployment, or official-client workflow was performed for this implementation. Historical client runs describe their recorded sources only.

## Compilation

The complete production Gall agent and its real imports compile against the declared Zuse **408**, using stock Vere **4.6** and the actual Hoon 135, Arvo 234, Lull 320 and Zuse 408 sources. The standalone attachment and key-normalization helpers also compiled during development.

The [compilation receipt](compilation.json) records the native result, compiler and adapter hashes, and every input hash. Paths are normalized for portability. Source bytes were unchanged during compilation. The native agent type and code mugs are `2025734632` and `737012529`.

The Arvo/kernel inputs match [urbit/urbit commit `5a187fededc4582a34fcd6055c67bb63e0917b94`](https://github.com/urbit/urbit/tree/5a187fededc4582a34fcd6055c67bb63e0917b94) byte-for-byte, including resolved `pkg/base-dev` library symlinks. Vere's embedded Ivory environment reports Zuse 410, so the build uses the upstream [`+solid` compiler bootstrap](https://github.com/urbit/urbit/blob/5a187fededc4582a34fcd6055c67bb63e0917b94/pkg/arvo/lib/pill.hoon#L206-L219) to compile all subsequent types in the matching Hoon 135 environment. It constructs compiler/library/agent cores without invoking Arvo lifecycle gates, Gall lifecycle arms, or requests. Bootstrap jet-registration diagnostics do not replace the final successful result.

Reproduce with a checkout of that Urbit source and the Vere executable recorded in this repository's `toolchain.json`:

```sh
python3 scripts/compile_desk.py \
  --vere /path/to/vere-v4.6 \
  --arvo-root /path/to/urbit/pkg/arvo \
  --output-dir /tmp/bitwarden-compile
```

The command writes live compiler logs and a receipt. Its success condition requires the actual returned completion tag and Kelvin, exit status, and unchanged source hashes. It is a build command, not a runtime compatibility test.

## Source and asset checks

The complete change received source review of state migration, bulk atomicity, attachment ownership/byte transfer, key rotation and official request shapes. Review fixes include the attachment deletion response, iOS upload revision preservation, stale clone attachment metadata, and clearing the previous user-key ID only after successful rotation. The original `%0` session revocation remains; `%1` state migrates without discarding existing sessions or content.

JavaScript syntax, Python syntax, changed Markdown local links and Git whitespace checks pass. Every generated asset entry exactly matches its current web source. Actual static assets were rendered at desktop and 390 × 844 mobile widths; the public/error-state layout was inspected. No fake bootstrap response was supplied, so this does not claim authenticated summary or client workflow verification.

The source package is built with the unchanged local Connect checkout and verifies deterministic archive generation and every manifest hash:

```sh
node --check web/app.js
URBIT_CONNECT_ROOT=/path/to/urbit-connect PYTHONDONTWRITEBYTECODE=1 python3 scripts/package.py
```

The generated `dist/urbit-bitwarden-source.tgz.sha256` belongs alongside its archive. Connect source commit `a5d709c0b2dc14b99be5d23434b9d88eeaf05320` is build provenance, not a compatibility pin. No Connect change is required for the personal-vault API additions.

## Remaining evidence boundary

The new server contracts have not been exercised through installed official clients or a deployed desk in this change. The inspected installed clients do not expose every management operation: user-key rotation remains web-vault-only, and CLI 2026.9.1 has no vault-purge command. Icons use direct website-favicon redirects rather than Vaultwarden's cache/discovery. These concrete boundaries are documented in the [implementation notes](../../docs/personal-vault-api.md); no timed trial or readiness gate is introduced.
