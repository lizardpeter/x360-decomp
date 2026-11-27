# Metro native integration

This branch consolidates the storage-notification signed status fix, checked I/O and console configuration, isolated writable HDD cache, dynamic retail module identity, original XAM routing, and controller statistics status fix. The original guest remains authoritative; no replacement UI, no bypass of its startup worker, and no fabricated statistics.

The connected-input suite now uses the SDK's real input system with its existing deterministic fake hardware driver and actual guest-thread kernel export dispatch. It exercises two independent contexts, callback ABI, assigned ports, repeated announce, real endian state/capability outputs, packet transitions, optional outputs, rejected overlapping/out-of-range buffers, unavailable statistics and reset behavior. The capture script now requires evidence of successful guest consumption of pad changes, not just input received by the host provider. Images still need visual inspection.

The parent storage-only, cache-only, and statistics branches remain available as independent comparisons. Integration does not imply verified boot; the tests and actual dashboard capture must complete successfully.
