#pragma once
#include "abi/import_provider.hpp"
#include <span>
namespace x360::host {
// Explicit nonblocking hosted dispatcher objects. No scheduler or host handles.
class DispatcherObjects {
public:
    static abi::ImportCallResult wait_addresses(std::span<const abi::Address> addresses,
        std::uint32_t kind,std::uint32_t mode,std::uint32_t alertable,abi::Address timeout,
        abi::GuestCall& state,abi::GuestMemory& memory);
    static abi::ImportCallResult call(std::uint16_t ordinal,abi::GuestCall& state,abi::GuestMemory& memory);
};
}
