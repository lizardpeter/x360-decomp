#pragma once
#include "execution/dispatch.hpp"
#include "machine/address_space.hpp"
namespace x360::launcher {
// Composition root, not a complete dashboard launcher. Owns its memory and
// registry, with no dependencies from original subsystems back into this layer.
class Metro17559 {
public:
    Metro17559();
    execution::DispatchResult call(abi::Address address,abi::GuestCall& state) const;
    machine::AddressSpace& memory() noexcept{return memory_;}
    std::size_t registered_functions() const noexcept{return dispatch_.size();}
private:
    execution::Dispatch dispatch_;
    machine::AddressSpace memory_;
};
}
