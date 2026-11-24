# Roadmap

1. Reproducible original source intake, PIRS and XEX2 header inventory.
2. Obtain validated decoded executable images; distinguish each encoding, build and module. Verify image bounds and source provenance.
3. Ghidra PowerPC analysis: functions, pseudocode, disassembly, imports by ordinal, resources, cross-references. Record function boundaries and name evidence independently for dash and XAM.
4. Faithful reconstruction of local dashboard logic, XUI resources/animations and navigation; test functions against original behavior.
5. Native host service boundary: rendering, input, audio, local profiles and storage. Track every unsupported service explicitly. Establish boot → Home → Guide → navigation before broader compatibility.
6. Enhanced build: optional resolution, frame pacing, input and renderer improvements only after faithful behavior has evidence. Keep independent tests and change ledger.

7. Expand to whole-system boot, hypervisor, kernel, device drivers and additional firmware profiles using the existing OS-wide component boundaries. See architecture.md.

Static recompilation is a parallel route to hosted execution, not a replacement for evidence-backed authored source. No working dashboard build or whole-system boot is claimed yet.
