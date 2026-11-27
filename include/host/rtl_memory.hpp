#pragma once
#include "abi/import_provider.hpp"
namespace x360::host {
// Bounded, independent hosted RTL services. Not original kernel bodies.
class RtlMemory {
public:
    static abi::ImportCallResult call(std::uint16_t ordinal,abi::GuestCall& state,abi::GuestMemory& memory);
};
}
