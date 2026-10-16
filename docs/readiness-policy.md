# Development and readiness policy

Owner direction, 2026-10-16: remove arbitrary content quotas and readiness gatekeeping. Do not run synthetic fixtures, soak tests, elapsed-time trials or tester/operator/developer quotas. This direction remains in effect for subsequent work unless the owner explicitly changes it. No fixed-duration observation, certification label, independent-signoff count or matching historical-evidence hash is a prerequisite for daily use.

Record actual supported workflows, observed failures and implementation gaps. Preserve old receipts and plans as dated history; their gates and synthetic-data-only instructions do not govern current work. Never reinterpret removing a gate as passing it, and never present historical client results as new verification of changed code.

Use source review, syntax/type/build checks and deterministic packaging by default. Actual official-client workflows on an identified user setup require task authorization. The current cleanup uses only static/build verification. It does not deploy to a ship or run client acceptance, synthetic or soak tests. Operational target checks, authentication, authorization, conflict/atomicity rules, source integrity and backup path/lock protections remain in force. They protect the action or data rather than award a readiness label.

The [Vaultwarden comparison](vaultwarden-parity.md) defines the personal-content target. Connect remains the only authentication and authorization path. A local vault password decrypts keys; it must not become a second backend login method. [Resource controls](resource-controls.md) lists removed quotas and controls that remain.
