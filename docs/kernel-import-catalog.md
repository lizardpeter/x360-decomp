# Kernel import inventory and reconstruction priorities

All 519 distinct original kernel import ordinals across dashboard and XAM have names and function/variable classifications in analysis/modules/kernel-import-catalog.tsv. Original slot counts come from hash-verified retail images. The names and kinds are external annotations from the Xenia project, pinned revision 95a5c3ee250f80c3b9d139658649d9ffb6db3eec, file src/xenia/kernel/xboxkrnl/xboxkrnl_table.inc (BSD license; copyright 2021 Ben Vanik). Reference: https://github.com/xenia-project/xenia/blob/95a5c3ee250f80c3b9d139658649d9ffb6db3eec/src/xenia/kernel/xboxkrnl/xboxkrnl_table.inc . No Xenia implementation code is incorporated. The annotations do not establish the original kernel's implementation or signature.

The audit checks all 1,490 original kernel import slots (498 function and 21 variable ordinals, 244 ordinals shared between modules) and independently scans exception-directory ranges for direct linked branches to kernel thunks: 6,271 in the dashboard and 8,567 in XAM, 14,838 combined. These are static call sites, not runtime frequency; indirect calls, missing leaf functions and function pointers are not included. The generated local report sorts the two observed startup blockers first and then by descending direct call count.

First startup boundaries:
- 0193 XexExecutableModuleHandle, variable. Dashboard loads the imported pointer before dereferencing an executable module object. Do not substitute a made-up success or arbitrary pointer; define and test the hosted loader object contract separately.
- 0015 ExRegisterTitleTerminateNotification, function. XAM reaches this import during the synthetic attach sequence; reconstruct the registration contract before proceeding.

All entries are currently marked missing. A host adapter is not a faithful original kernel reconstruction and must be tracked separately. No generated firmware or external implementation is published.
