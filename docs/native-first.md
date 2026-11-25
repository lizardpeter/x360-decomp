# First authored native functions

The native dashboard library implements a verified identical 12-byte leaf pattern at 47 distinct original function entries. The names remain address-based because their application-level purpose has not been established. This is 47 equivalent original entry points, not 47 distinct algorithms.

The execution registry is module-qualified and rejects invalid or duplicate registration atomically. Unregistered calls return unresolved and do not change guest state; no fake success or recompiler fallback is supplied. The minimal integer call frame is not a full Xenon CPU model.

The independent narrow instruction-reference test runs 256 deterministic varied guest states per binding (12,032 cases). The original evidence audit checks the pinned source XEX, page hashes, decoded image hash, original exception-directory sizes and exact instruction pattern for the full set. It is not an original-executable hardware differential test; ledger status is conservative. No dashboard startup or GPU implementation is claimed.

```sh
cmake -S . -B build/native -DCMAKE_BUILD_TYPE=Release
cmake --build build/native
ctest --test-dir build/native --output-on-failure
python tools/fetch_originals.py --only dash_basic
python tools/verify_native_leaf.py
```
