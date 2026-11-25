#pragma once
#include "execution/module_registry.hpp"
#include "abi/guest_memory.hpp"
namespace x360::execution {
enum class BootstrapStop {budget,return_address,import_value,import_thunk,unsupported_instruction,access_fault,non_executable};
struct BootstrapTrace {abi::Address address;std::uint32_t word;};
struct BootstrapResult {
    BootstrapStop stop{};
    std::size_t retired{};
    abi::Address address{};
    std::uint16_t ordinal{};
    std::string library;
    std::vector<BootstrapTrace> trace;
};
// Restricted reference path for verified integer startup sequences. Not a
// general interpreter, static recompiler, or implementation of the kernel.
BootstrapResult bootstrap_ppc(const ModuleManifest& module,abi::GuestMemory& memory,
                              abi::GuestCall& state,abi::Address return_address,std::size_t budget);
}
