# Native hosted object and pool services

This is an opt-in title-local compatibility layer for the independent runtime, not a claim of reconstructed retail kernel internals. It uses the pinned SDK's documented export signatures as interface evidence. The AOT dashboard still uses the SDK's separate kernel provider.

Eleven NT object exports now share actual guest-backed dispatcher state: NtCreateEvent, NtCreateSemaphore, NtClearEvent, NtSetEvent, NtPulseEvent, NtQueryEvent, NtReleaseSemaphore, NtDuplicateObject, NtClose, NtWaitForSingleObjectEx and NtWaitForMultipleObjectsEx. Handles are monotonically allocated, aliases refer to the same object, and the final handle releases the guest reservation. The shared wait implementation validates the entire set before consuming signals; no sleeping or fabricated scheduler success. Named objects, object attributes, external references, mutant/timer objects and APC delivery remain unsupported. A title-local handle is not a host OS handle.

The pool implements ExAllocatePool, ExAllocatePoolWithTag, ExAllocatePoolTypeWithTag, ExFreePool and a hosted requested-size query (ExQueryPoolBlockSize). The first three follow the small-header versus page-aligned allocation boundary in the pinned SDK. Each allocation uses its own bounded guest reservation, fresh zeroed backing, and ownership tracking. The query returns the requested size rather than asserting undocumented retail rounded-block-size semantics. A bad or interior free remains unsupported. This is intentionally a correctness-first allocator, not a production slab implementation. 

All adapters require explicit enable_kernel_services and preserve the earlier diagnostic profiles. CI exercises handle aliasing, stale handles, object types, semaphore limits, immediate wait-all/any, event query/pulse/clear and the allocation lifecycle. Runtime integration into the graphical AOT host and original executable differential validation remain outstanding.

Reference: https://github.com/rexglue/rexglue-sdk/tree/a3e1d82678ca20d68d4837a8e9ee4652ff073745/src/kernel/xboxkrnl (threading, ob, memory).
