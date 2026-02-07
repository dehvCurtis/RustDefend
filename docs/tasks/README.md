# RustDefend Task List

## Priority Order

| # | Task | Priority | Status | Impact |
|---|------|----------|--------|--------|
| 1 | [Severity Recalibration](01-severity-recalibration.md) | P0 | DONE | Reduced false-critical findings (CW-001, CW-002, INK-002, SOL-009) |
| 2 | [INK-003 Precision](02-ink003-precision.md) | P0 | DONE | Risk-stratified INK-003 (Critical/High/Medium/Low based on field type) |
| 3 | [SOL-003 FP Reduction](03-sol003-fp-reduction.md) | P1 | DONE | SOL-003: 488→131 on SPL (73% reduction). Division/widening/pack/saturating filters |
| 4 | [New 2024+ Detectors](04-new-detectors-2024.md) | P2 | DONE | Added 8 new detectors (32→40). SOL-010/011, CW-009, NEAR-009/010, INK-009/010, DEP-001 |

## Final State

- **40 detectors** across 4 chains + cross-chain DEP-001
  - Solana: 11 (SOL-001 through SOL-011)
  - CosmWasm: 8 (CW-001 through CW-009)
  - NEAR: 10 (NEAR-001 through NEAR-010)
  - ink!: 10 (INK-001 through INK-010)
  - Cross-chain: 1 (DEP-001)
- **95 unit tests**, all passing
- Severity levels calibrated to 2024+ ecosystem reality
- SOL-003 FP rate reduced by 73% on SPL
- New detectors covering: PDA seed safety, rent exemption, address validation, storage key safety, deposit checks, delegate call safety, payable consistency, dependency vulnerabilities
