#pragma once
#include "abi/import_provider.hpp"
namespace x360::host {
// Single-thread diagnostic lock model. The guest owner identity is an
// explicit caller configuration, not a fabricated kernel thread object.
class CriticalSections {
public:
    static abi::ImportCallResult initialize(abi::GuestCall& state,abi::GuestMemory& memory,bool with_spin);
    static abi::ImportCallResult enter(abi::GuestCall& state,abi::GuestMemory& memory,abi::Address owner,bool try_only);
    static abi::ImportCallResult leave(abi::GuestCall& state,abi::GuestMemory& memory,abi::Address owner);
};
}
