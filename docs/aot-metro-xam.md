# Metro dashboard/XAM AOT integration trial

Run [45642721888](https://github.com/lizardpeter/x360-decomp/actions/runs/45642721888) passed strict dashboard generation after the XEX repeated-record correction. Native link diagnostics identify five unresolved addresses. All five are original XAM thunks and every ordinal has an address in the independently extracted XAM export inventory:

| Ordinal (hex) | Dashboard thunk | Retail XAM address |
|---|---|---|
| 0546 | 9293C8BC | 8168EB50 |
| 0547 | 9293C89C | 8168EB88 |
| 0548 | 9293C8AC | 8168EBC0 |
| 0549 | 9293C88C | 8168EBF8 |
| 054B | 9293CE6C | 816DEF20 |

The pinned SDK's XAM catalog omits these ordinals. Its register phase treats unknown ordinals of known kernel libraries as ordinary unresolved imports, so no module forwarding bodies are generated. The SDK already supports multi-binary code generation, generated module-import forwarding bodies, and an explicit fatal error when an export cannot be resolved.

The new trial stages the hash-verified dashboard and XAM together, preserves the existing verified entry hints, and narrowly classifies only the five known (image base, library, ordinal, thunk) tuples as module imports. All other unknown ordinals retain the original diagnostic behavior. It does not introduce no-op exports, patch original binaries, bypass verification, or run guest code. CI checks strict code generation, native dashboard linking and production of the separate XAM library; it retains only metadata.

**Pending:** SDK runtime treats XAM as a built-in kernel library and does not automatically load original XAM for dashboard dependencies. A successful link alone will not establish boot. Runtime composition must explicitly load/register the correct original module before resolving these imports; guest entry ordering and the interaction between hosted XAM services and native XAM must be verified separately. Do not run this trial as if it were an interactive dashboard. The independently authored runtime remains the long-term faithful replacement boundary.


## Verified XAM data import

The dashboard also imports XAM ordinal 0x03DB, g_XuiAutomation, as a variable (not a callable thunk). The original import inventory places its value slot at 0x92000550; the original XAM export inventory places the symbol at 0x81A87F20. The latter is checked against the hash-verified XAM image and must fall inside a writable, non-executable loaded data section. The loader patch writes this original guest address only for the exact dashboard base, library, ordinal, slot, and SDK export name. This makes the dashboard's variable import refer to the actual mapped retail XAM data, rather than the SDK's unresolved-variable marker. The other missing variable imports are not fabricated.

## Live import relocation and diagnostics

The native mapping gate now checks the exact loaded XEX import metadata, the mapped XAM export, and the actual big-endian guest value. It reports all five code slots with their expected/observed values. A still-unresolved original descriptor may be relocated only after both images and both registered function addresses have been verified. A data import is verified as non-executable writable XAM data. Read-only import pages are temporarily made writable only for the relocation and are restored immediately. Unknown values and missing records remain fatal; no guest call is substituted. The graphical boot uses the same verification and requires the data binding as well.
