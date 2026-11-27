#pragma once
#include "abi/import_provider.hpp"
#include "machine/address_space.hpp"
#include <map>
namespace x360::host {
// Bounded title-local pool with tracked allocation ownership. The physical
// host address and allocator internals are never exposed to guest code.
class KernelPool {
public:
    explicit KernelPool(machine::AddressSpace& memory):memory_(memory){}
    KernelPool(const KernelPool&)=delete;
    KernelPool& operator=(const KernelPool&)=delete;
    ~KernelPool();
    static bool handles(std::uint16_t ordinal) noexcept;
    abi::ImportCallResult call(std::uint16_t ordinal,abi::GuestCall& state,abi::GuestMemory& memory);
private:
    struct Allocation {abi::Address base;std::uint32_t size;};
    machine::AddressSpace& memory_;
    std::map<abi::Address,Allocation> live_;
    static constexpr abi::Address arena_begin=0x52000000,arena_end=0x58000000;
};
}
