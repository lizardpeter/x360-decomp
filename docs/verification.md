# Verification

Run unittest for synthetic malformed/truncated and repeated-import fixtures. Run tools/analyze.py on hash-verified originals to establish real-source evidence. It writes JSON under analysis/ and records actual header counts, not unique function counts. XEX import entries are address slots, which can include thunk/data pairs; a later decoded-image pass is required for ordinal resolution and unique import counts.

The original PIRS package is hash-pinned, and the extracted dashboard and XAM are independently checked against their expected SHA-256. This does not verify Microsoft signatures or every STFS hash-tree block. For function parity, future tests must compare machine-state and observable effects for specific inputs; no status may be promoted to matches without a reproducible test.
