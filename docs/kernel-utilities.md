# Hosted kernel utilities

The independent native runtime adds opt-in string descriptors, bounded ASCII comparisons, Latin-1/UTF-16 conversion, standard incremental CRC-32, 100-ns host clock services, Gregorian UTC time conversion, and explicit process-wide TLS slot allocation with independent guest-thread banks. These are hosted implementations of documented ABI contracts, not recovered original kernel bodies.

RtlCompareStringN follows the pinned SDK common-prefix bounded comparison and 0xFFFF NUL-terminated sentinel; non-ASCII case folding is deliberately unresolved. RtlCopyString/RtlCopyUnicodeString use the declared buffer capacity and copy bytes without an invented terminator. RtlMultiByteToUnicodeN and RtlUnicodeToMultiByteN use the pinned SDK's Latin-1 conversion behavior, not an arbitrary host locale. Unsupported UTF-8 and Unicode case mappings remain separate. The CRC uses the standard reflected polynomial and independent known-answer tests.

The clock uses a host steady-clock origin for interrupt time, 10 MHz 100-ns units as its explicit hosted performance frequency and UTC system time for KeQuerySystemTime. It does not claim hardware timer fidelity. RtlTimeFieldsToTime and RtlTimeToTimeFields handle the 1601–9999 Gregorian range, with bounded guest layouts and no timezone conversion. Deterministic samples allow testing absolute and relative values independently of wall clock.

TLS has 256 slots according to the pinned SDK process bitmap evidence. Freeing or recycling a slot clears it in all registered threads. Current thread identity is explicitly assigned; no real scheduler or thread migration is claimed. These services remain independent of AOT and do not change the previous trace profiles unless enabled. Tests exercise CRC chaining, truncated conversions, fault atomicity, leap years and slot exhaustion/reuse.

Reference: pinned ReXGlue SDK a3e1d82678ca20d68d4837a8e9ee4652ff073745, xboxkrnl_rtl.cpp, xboxkrnl_threading.cpp, thread_registry.cpp.
