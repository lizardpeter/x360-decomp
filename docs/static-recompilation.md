# Static PowerPC recompilation plan

Use verified loaded images and function/control-flow inventories as input. Evaluate ReXGlue SDK (pinned reference in target.toml) or XenonRecomp for Xenon instruction support before selecting a translator. Ghidra pseudocode is analysis evidence, not compilable recompilation input.

Translate original PPC machine instructions ahead of time to C++ or IR, compile for the host, and retain guest CPU and memory semantics. Generated code calls the runtime for dynamic branch dispatch, module import resolution and device-facing services. The hosted Metro profile can initially execute generated dashboard/XAM logic while native providers satisfy the required kernel contracts. A future full-system profile can select reconstructed kernel, hypervisor and driver providers. The same dispatch map can select hand-authored functions by module/guest address once differential tests establish parity.

Acceptance gates: instruction semantics (including VMX128), import/ordinal and relocation coverage, indirect control flow, thread and exception behavior, original startup trace, Home/Guide navigation, reproducible build without executing original PPC binaries. Running translated code is not equivalent to source decompilation or a complete OS. Generated code and original assets are distinct; neither is automatically permitted for public redistribution. An experimental translator lane is now configured; it has not yet produced a bootable build.


## Initial AOT trial

Use ReXGlue v0.11.0 as a separate experimental translator; the Linux amd64 release archive is pinned by SHA-256 in the workflow. This differs from the earlier v0.10.0 source reference. Stage the exact compressed dashboard and PIRS-extracted XAM by original hashes, then generate separate minimal manifests. This trial supplies no copied hints, forced code generation, privilege bypasses, or host-service overrides. A failed codegen run is diagnostic, not a reconstructed function count.

The jobs test strict code generation only. Original XEX inputs are never executed, and generated C++ remains in ignored build directories. Public CI publishes counts and hashes only, not generated source, firmware, assets or logs. The next gates are resolving missing control-flow targets, compiling/linking generated code with an appropriate host ABI, selecting authored function overrides, and integrating graphics, input and kernel services. The authored runtime and existing reference tests remain independent.

Reference: https://github.com/rexglue/rexglue-sdk/releases/tag/v0.11.0 .
