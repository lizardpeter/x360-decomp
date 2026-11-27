# Original XAM heap initialization and second native boot fault

The storage-notification crash was resolved in the original graphical boot
run 45944345779. The next repeatable fault is a read at guest PC 8169D068
with effective address 00000274. Static decoding of the exact original
17559 XAM image locates the null object at 81A9F850. Its only verified writer
is 816A17B8: it requests 6536 bytes through 816E6C78, constructs the object
through 8169BFA0, and stores the result at 816A17F0. XAM's original process
attach calls this writer at 816969DC but does not check its result.

The heap is not being replaced. The original allocator 816E6C78 dispatches
through 816E63D8 and 816E5D58 to the original native-recompiled allocator
8171F630. The original initializer 816E6618 sets up eight heap descriptors
with 28-byte strides; their creation uses original 8171F060. The full
bounded construction graph (87 functions) and call operands were verified
in run 45946781502.

One demonstrable hosted-kernel mismatch is the region selector: original
8171F264-8171F280 selects region 3 when the heap flag 00080000 is set and
KeGetCurrentProcessType returns 1; the pinned SDK rejected all regions above
2. Query, reserve, commit, protect and free now share the accepted region
range 0..3. The hosted address space is still unified, as before; this
does not claim fully independent console process memory spaces.

The memory exports now validate guest input/output pointers and range
arithmetic, round both endpoints, translate old protection back to guest
flags, and clear only newly committed pages. The exact source and tests are
applied to the pinned SDK during the build. The previous graphical crash
has not yet been demonstrated fixed by these changes.

To determine the remaining cause without bypasses, the native graphical
build records actual VM API results and original guest ABI values at
verified heap/constructor PCs. Generated instrumentation is bounded,
environment-gated, and leaves original instructions and image bytes
unchanged. Missing required markers abort instrumenting before writing.
The generated source stays local; only metadata and boot logs are retained.

## System process attachment

Original scalar execution evidence (run 45947941331) confirms that the
same 6536-byte system-object allocation selects descriptor 0 (81AABFF8)
when the thread is a user/title process with no per-thread object, but
descriptor 1 (81AAC014) when it belongs to the system process with no
per-thread object. The original initializer explicitly clears descriptor
0 and constructs descriptor 1. This explains why running the system DLL's
process-attach on the dashboard title thread is an invalid boot context.
The precise live allocator return still requires the instrumented boot.

The hosted SDK already has distinct idle, title and system KPROCESS
objects and per-process TLS allocation bitmaps. XAM attach now runs the
unmodified original entry in a real system-process kernel worker with its
own guest stack, KPCR, KTHREAD and TLS; the dashboard entry remains on
its original title thread. The title waits for actual attach completion,
retains the original return value and fails on a timeout or zero return.
Controller binding notifications use the same system context. No process
type export is overridden and no missing heap pointer is manufactured.
Regression tests exercise the actual dispatcher, process identity, TLS
isolation and original return semantics.

### Subsequent recovery-state checks

The original worker at `81696558` compares the return of `DumpGetRawDumpInfo` (call at `816965D4`) with zero and only reads byte 5 of its output structure when it is nonzero. A generic void stub leaves the output pointer in r3, incorrectly suggesting that a console crash dump exists. The hosted implementation returns false without writing the unknown structure. At `81696628`, `HalGetNotedArgonErrors` returns a recorded error bitmask; the caller tests bits 0–2 to select its recovery state. Since this runtime has no persisted Argon hardware-error record, it returns the empty bitmask rather than stale r3. Neither implementation claims physical hardware support or suppresses a reported host failure. Actual boot confirmation remains necessary.
