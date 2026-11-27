#pragma once
#include "abi/import_provider.hpp"
namespace x360::host {
// Explicit nonblocking hosted dispatcher objects. No scheduler or host handles.
class DispatcherObjects {
public:
    static abi::ImportCallResult call(std::uint16_t ordinal,abi::GuestCall& state,abi::GuestMemory& memory);
};
}
