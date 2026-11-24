# Decoded-image analysis

The unencrypted retail XEX2 images are decoded without executing original code. Basic compression and LZX compression are handled separately; all compressed LZX blocks and XEX page digest-chain links are verified. This is not a signature verification.

The LZX adapter is a small authored interface to a separately supplied libmspack decoder. The independently obtained x360-native v1.34.6 Linux x64 release includes its LGPL decoder and headers; its archive is pinned in the validation workflow. No original code, fonts, key material or decoder library is committed. Reference for the XEX page digest layout and .pdata packing: x360-native v1.34.6, src/content/xex_patch.cpp and src/content/main.cpp (BSD-3-Clause), and ReXGlue's xex_module.cpp.

```sh
# Assuming the reference release has been extracted locally:
APP=/absolute/path/to/x360-native-1.34.6-linux-x64/app
mkdir -p build
cc -shared -fPIC -O2 -I"$APP/workspace/licenses/sources/libmspack" tools/lzx_adapter.c -L"$APP" -lx360n-mspack -Wl,-rpath,"$APP" -o build/lzx_adapter.so
python tools/analyze_decoded.py --lzx build/lzx_adapter.so
```

Analysis outputs are metadata only: decoded image hashes and section ranges, actual imported ordinals (merging duplicate library records), resource hashes, exception-table function ranges and direct branch-and-link call edges. Indirect calls, unclassified targets, leaf discovery and Ghidra decompilation are separate later passes. Resource bytes and loaded images stay in originals/. Do not mistake data-only modules for PE files. Encrypted inputs are explicitly skipped, not silently treated as decoded. No kernel/XAM services or dashboard functions are claimed reconstructed by these tools.
