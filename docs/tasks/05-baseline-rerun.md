# Task 5: Baseline Re-run (40 Detectors)

**Priority:** P1
**Status:** DONE
**Date:** 2026-02-13

## Goal

Re-run the ground truth baseline with all 40 detectors (up from 32) against pinned test corpus commits to establish a reproducible measurement of scanner coverage and accuracy.

## Changes

- Rebuilt release binary with all 40 detectors
- Pinned all 7 test corpus repositories to specific commit hashes
- Ran full scans in JSON format across all corpora
- Rewrote `GROUND_TRUTH_BASELINE.md` with complete results

## Results

| Corpus | Findings |
|--------|----------|
| Solana/SPL | 318 |
| Solana/Anchor | 111 |
| CosmWasm/cw-plus | 43 |
| CosmWasm/core | 73 |
| NEAR/sdk-rs | 27 |
| NEAR/near-ft | 5 |
| ink!/examples | 114 |
| **Total** | **691** |

- **691 total findings** (up from 605 with 32 detectors)
- **+86 new findings** from Task 4 detectors: SOL-010 (+48), NEAR-010 (+19), CW-009 (+17), INK-010 (+6), SOL-011 (+2)
- **~56% estimated true positive rate** (down from ~59% due to SOL-010 FPs on Anchor codegen)
- **95 unit tests**, all passing
- **No regressions** in any of the original 32 detectors
- 11 detectors with zero findings documented with reasons
- Coverage gaps updated to reflect 2024-2026 threat landscape

## Pinned Commits

| Corpus | Commit |
|--------|--------|
| SPL | `264ca72de06b0c2b45c0b15d298000fe3f82db2e` |
| Anchor | `2cb7ababa7dba3ac269fd2e60cfa06793ad2b989` |
| cw-plus | `1e96e98d19e5289f97eb9173e961c750d443a40f` |
| cosmwasm | `6e4803514633f2cc5e7091126a7e7b487fb7015c` |
| near-sdk-rs | `9ed4b6489ca3588024e1f9a18ead69f802446688` |
| near-ft | `7721a49423466bcd1104369dcea50229e64282fd` |
| ink-examples | `1b8ff1e250669bf1679acdf3aa47a6d43e4e2256` |
