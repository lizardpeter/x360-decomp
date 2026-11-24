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
