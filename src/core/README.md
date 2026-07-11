# Core (the audited security path)

Everything under `src/core/` counts toward the ≤1,500-LOC legibility budget
(R9) and must have **zero** runtime dependencies beyond the Bun/Node stdlib.
Bun-specific imports (`bun:*`) are forbidden here — they live in
`src/adapters/` (enforced by `scripts/lint-bun-imports.ts`).

Planned modules (design §2):

| dir | responsibility | ~LOC |
|---|---|---|
| `proxy/` | listen, strip `/run/<uuid>`, upstream pool, forward raw, read-once pump | 340 |
| `otlp/` | local OTLP/HTTP receiver (Mode B) | 120 |
| `normalize/` | proxy/OTLP input → canonical `Exchange`; auth-header scrub | 120 |
| `scanner/` | keyword prescan → regex → entropy → checksum → tier → fingerprint | 350 |
| `session/` | conversation-key derivation (R4 ladder) | 120 |
| `alert/` | fingerprint dedup, event upsert, alert emission | 120 |
| `store/` | schema, write path, queries, retention/secure purge | 250 |
| `config/` | user config, vendored rule files, allowlists | 80 |
