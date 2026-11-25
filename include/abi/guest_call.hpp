#pragma once
#include <array>
#include <cstdint>

namespace x360::abi {
// Minimal integer call state. Not a complete Xenon CPU or a guest memory layout.
// Additional architecture state belongs in independent, explicit contracts.
using Address = std::uint32_t;
struct GuestCall {
    std::array<std::uint64_t,32> gpr{};
    std::uint64_t lr{}, ctr{};
    std::uint32_t cr{}, xer{};
    Address pc{};
    bool operator==(const GuestCall&) const = default;
};
using Function = void (*)(GuestCall&) noexcept;
struct FunctionBinding {
    Address address;
    Function implementation;
};
}
