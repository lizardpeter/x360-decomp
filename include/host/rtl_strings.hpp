#pragma once
#include "abi/import_provider.hpp"
namespace x360::host {
class RtlStrings {
public:
    static bool handles(std::uint16_t ordinal) noexcept;
    static abi::ImportCallResult call(std::uint16_t ordinal,abi::GuestCall& state,abi::GuestMemory& memory);
};
}
