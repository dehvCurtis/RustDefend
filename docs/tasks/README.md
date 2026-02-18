# RustDefend Task List

## Priority Order

| # | Task | Priority | Status | Impact |
|---|------|----------|--------|--------|
| 1 | [Severity Recalibration](01-severity-recalibration.md) | P0 | DONE | Reduced false-critical findings (CW-001, CW-002, INK-002, SOL-009) |
| 2 | [INK-003 Precision](02-ink003-precision.md) | P0 | DONE | Risk-stratified INK-003 (Critical/High/Medium/Low based on field type) |
| 3 | [SOL-003 FP Reduction](03-sol003-fp-reduction.md) | P1 | DONE | SOL-003: 488→131 on SPL (73% reduction). Division/widening/pack/saturating filters |
| 4 | [New 2024+ Detectors](04-new-detectors-2024.md) | P2 | DONE | Added 8 new detectors (32→40). SOL-010/011, CW-009, NEAR-009/010, INK-009/010, DEP-001 |
| 5 | [Baseline Re-run (40 detectors)](05-baseline-rerun.md) | P1 | DONE | Re-ran ground truth baseline with all 40 detectors against pinned test corpus. 691 findings, ~56% TP rate |

## Final State (v0.5.0)

- **61 detectors** across 4 chains + cross-chain dependency/build analysis
  - Solana: 21 (SOL-001 through SOL-021)
  - CosmWasm: 13 (CW-001 through CW-013)
  - NEAR: 12 (NEAR-001 through NEAR-012)
  - ink!: 11 (INK-001 through INK-011)
  - Cross-chain: 4 (DEP-001 through DEP-004)
- **225+ unit tests**, all passing
- Custom rules engine (TOML-defined pattern rules, --rules flag)
- Cross-file call graph analysis (--cross-file flag)
- MIR analysis foundation — AST-level type inference (--type-aware flag)
- VS Code extension scaffold (vscode-extension/)
- Web dashboard scaffold (dashboard/)
- crates.io publishing metadata
- Intra-file call graph analysis for FP reduction
- Workspace-aware chain detection for monorepos
- Baseline diff and project config support for CI workflows
- Incremental scan caching for fast re-scans
- Severity levels calibrated to 2024+ ecosystem reality
- Ground truth baseline established with pinned commits (see [GROUND_TRUTH_BASELINE.md](../../GROUND_TRUTH_BASELINE.md))
