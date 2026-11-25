# First original entrypoint execution

The bounded reference runner executes a narrow integer PowerPC subset against the original decoded module mapping, not a translated or authored replacement of the whole module. It supports observed prologue saves, loads/stores, addi/addis, immediate OR, register OR, LR/CTR moves, non-wrapping rlwinm masks, compare, direct branches, simple CR-only branch conditions and unconditional returns/CTR branches. It records each attempted word and never treats unpatched import value words or thunk placeholders as valid pointers/instructions. Unsupported opcodes, inaccessible addresses, non-executable ranges and step limits stop explicitly.

Independent Python instruction reference, zeroed initial registers (except stack, return sentinel and XAM attach arguments), 64 KiB synthetic writable stack:
- Dashboard: 31 retired instructions; the next instruction attempts to read the kernel value slot 0x92000F60 (ordinal 403) at PC 0x92198944. Stop before interpreting its ordinal marker as a pointer.
- XAM: 58 retired instructions; stop at kernel thunk 0x81A72994 (ordinal 21). No fabricated API return.
- Verify trace, full integer state, stack and entire modified image SHA-256 separately for each module.

The initial conditions are diagnostic, not evidence of the real boot loader's complete state. The reference runner and Python comparison cover these startup prefixes, not exhaustive PowerPC correctness. The module loader still has no kernel service implementations, no patching or static recompilation backend, and no actual dashboard boot. All original bytes and snapshots stay temporary and are not published. The two blocked ordinals are the first concrete service dependencies under these initial conditions.
