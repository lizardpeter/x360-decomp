# Original source intake

All seven source objects are pinned in target.toml, representing the official update ZIP, standalone PIRS package, both dashboard encodings, shared resource archive, J-Runner and xeBuild reference ZIPs. The packages cover their extracted contents without storing duplicate copies in Git. Verify full files before use. The two complete font complements are local-only, hash-pinned in target.toml.

The PIRS payload contains full retail dash.xex and xam.xex as well as other modules. The .xexp and .xttp files are patches, not complete standalone executables/resources. Treat 17489 base data and modified xeBuild XAM variants as references, never as the retail 17559 target. No flash modification, credential material, or execution of downloaded tools is needed for intake.

The fetcher only extracts explicitly pinned members from a handoff ZIP, ignoring unrelated entries. The archive must be obtained through an authorized source. The source archives themselves remain intact. The initial PIRS reader is intentionally scoped to the observed contiguous, read-only, single-table layout, not a general STFS validator or signature verifier.
