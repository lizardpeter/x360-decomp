# Working in x360-decomp

Target: retail Metro V2 2.0.17559.0 (Xenon PowerPC, big endian). Preserve the original behavior in the faithful build; do not confuse PC x64 with the original architecture.

| Path | Responsibility |
|---|---|
| target.toml | Original build identities, SHA-256, R2 keys, references |
| analysis/<build>/ | Generated metadata, function inventory, future Ghidra exports |
| src/, include/ | Authored faithful reconstruction, original bugs retained |
| enhanced/ | Optional intentional overrides only |
| runtime/ | Native host boundary, service adapters and eventual executable |
| reconstructed_modules/ | Evidence-based XAM, kernel-facing and system-module reconstructions |
| records/ | Function status, names, bugs, patches with evidence |
| tests/ | Format validation and future differential tests |
| tools/ | Reproducible fetching, analysis, status and Ghidra tooling |

Generated files are produced by tools, never manually promoted. Address format: uppercase hexadecimal without 0x, at least eight digits; always qualify by build/module. Function status: located → named → typed → decompiled → compiles → matches → integrated. Imports are not reconstructed functions. A differential match requires reproducible comparison with original code and explicit test evidence. Enhanced changes require a patches.tsv entry and must not modify faithful behavior.

Keep copyrighted input binaries, firmware, fonts, keys, and large original archives out of Git history. R2 contains the source packages; all local input bytes are verified against target.toml. Never fetch or execute unrelated payloads from transfer artifacts. External projects remain separately attributed; do not copy their generated code or claim their tests as ours. Missing original functionality must fail explicitly, not return invented success.
