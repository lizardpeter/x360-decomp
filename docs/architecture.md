# OS-wide architecture

The project targets the Xbox 360 operating system, not a dashboard clone. Metro V2 17559 is the first profile. A hosted dashboard executable and future whole-system boot share the same components.

- Boot, hypervisor and kernel are separate original guest subsystems. Initially a hosted profile can substitute explicit compatibility providers for privileged operations; never label those providers faithful implementations of the kernel.
- Drivers and virtual hardware are separate: guest device logic consumes machine contracts; host adapters supply Windows/Linux/macOS/browser services. Real hardware support would be another target, not guaranteed by this design.
- XAM owns original XUI, profile and app services; dashboard and Guide are clients. Preserve module/ordinal identity and firmware version.
- Static recompilation belongs to the execution backend and generated/ignored build outputs, not authored source. Preserve 64-bit PowerPC registers, 32-bit guest addressing, big-endian memory, branch semantics, calling conventions and guest module relocations. Indirect calls dispatch by module and guest address. Imported functions resolve by library and ordinal through explicit contracts. Replace generated functions with tested authored implementations at the dispatch boundary. Unsupported instructions/services fail explicitly.
- Faithful/enhanced behavior, firmware profile, host platform and execution strategy are orthogonal. Do not maintain separate copies of the OS for each host.

The component registry is an acyclic allowed source-dependency graph. Original runtime callbacks or cycles cross ABI interfaces, not circular source imports. This structure reduces later moves but cannot guarantee no refactoring as original internals become known.

Full-system scope requires verified kernel/hypervisor/boot firmware evidence and device semantics beyond the current dashboard update. No full system boot, native executable or physical-console compatibility is claimed.
