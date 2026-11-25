# Ghidra pipeline

Ghidra 12.2, PowerPC:BE:64:64-32addr (64-bit registers, 32-bit guest addresses). The input is the independently verified loaded image; the raw binary loader maps it at the original XEX load address. SeedX360 sets section permissions, seeds original exception-directory ranges, and labels original import ordinals and XAM exports. ExportX360 attempts every Ghidra-discovered function, with a per-function decompiler timeout, and records all errors and missed seeds. The saved project remains available under the ignored build directory.

```sh
python tools/fetch_originals.py
python tools/analyze_decoded.py --lzx build/lzx_adapter.so
bash tools/ghidra/run.sh /path/to/ghidra_12.2_PUBLIC dash_17559
bash tools/ghidra/run.sh /path/to/ghidra_12.2_PUBLIC xam_17559
```

Full pseudocode and disassembly are sharded by 1,000 functions in build/ghidra/<module>/export/. These are generated analysis, not authored faithful source. The headless logs, missing-seed list, error inventory and summary distinguish successful and failed work. The project stores original machine bytes, so do not publish it in the public repository. Public CI exports the analysis inventory and summary only; run locally for the full project and code exports.

Standard PowerPC semantics do not cover all Xenon-specific VMX128 instructions; unrecognized instructions or misleading decompiler output must be recorded and addressed separately. Additional Ghidra functions are candidates, not proven original function boundaries. No successful run should be claimed before the summary and logs exist.

The first run aborted its seed script because the BinaryLoader program image-base property was zero even though the bytes were mapped correctly. Validate the actual memory extent, not that property. A fresh seed receipt is required, and the coverage gate now rejects missing seeds, empty disassembly, timeouts and decompiler failures. A failed coverage gate preserves diagnostics; it does not invalidate the underlying verified image.

The second run successfully seeded every original boundary but automatic analysis subsequently lost 3,889 dashboard and 2,000 XAM seeds. The two-session pipeline now captures heuristic discovery, reopens the saved project with auto-analysis disabled, contracts conflicting function bodies to authoritative ranges, and restores missing original entries only where a real instruction decodes. Rejected candidates are recorded rather than silently counted as code. A successful decompiler return on a one-byte non-code function is not a successful export. Original exception-directory extents are not proof that every word is executable: per-seed instruction bytes are recorded independently of span size. The final gate still requires every original start, a decoded entry, and zero decompiler failures; candidate validation and complete instruction semantics remain separate tasks.


## Xenon-specific analysis

The reconciled stock 12.2 runs restored all 42,149 exception-directory entries, but still failed to decompile one function in each image. Independently decoded original bytes identify dashboard instruction 924952EC = 18A20F34 (vspltw128) and XAM instruction 81A24E94 = 17FFF2F5 (vor128). The new default is the separately licensed, hash-pinned freeqaz Ghidra fork v12.1-vmx128 (Apache-2.0), with processor PowerPC:BE:64:Xenon. Its VMX128 semantics are a candidate, not assumed verified. A smoke check must decode the exact two instructions and extended registers and produce p-code before running real inputs. The stock baseline remains selectable via X360_GHIDRA_PROCESSOR=PowerPC:BE:64:64-32addr.

The CI matrix now covers all 14 distinct verified PE executables, not the duplicate dashboard encoding, four data-only modules, or two unsupported encrypted inputs. Full Ghidra exports remain local. The smoke check verifies decode and p-code presence, not exhaustive instruction semantics or correct reconstructed OS behavior.
