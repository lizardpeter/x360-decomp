#pragma once
#include "abi/import_provider.hpp"
#include "machine/address_space.hpp"
namespace x360::host {
// Restricted hosted implementation of the observed 64-KiB heap allocation
// requests. Other memory selectors, flags, and protection modes are not
// silently approximated.
class VirtualMemory {
public:
    explicit VirtualMemory(machine::AddressSpace& memory):memory_(memory){}
    abi::ImportCallResult allocate(abi::GuestCall& state,abi::GuestMemory& memory);
    static constexpr abi::Address arena_begin=0x30000000,arena_end=0x40000000;
private:
    machine::AddressSpace& memory_;
};
}
