#include "os/dashboard/memory_leaf_17559.hpp"
#include <bit>
namespace x360::os::dashboard {
namespace {
// Five verified entries, two distinct original register-allocation patterns.
// The result tests a nested 32-bit word against a constant. No semantic
// application-level name has been established.
abi::MemoryCallResult compare_17(abi::GuestCall& s,const abi::GuestMemory& m) noexcept {
    std::uint32_t pointer{},word{};
    if(!m.load_be32(static_cast<abi::Address>(s.gpr[3]),pointer)||!m.load_be32(pointer,word))
        return abi::MemoryCallResult::access_fault;
    s.gpr[10]=word;
    s.gpr[11]=std::countl_zero(std::uint32_t(0xc0000017u-word));
    s.gpr[3]=word==0xc0000017u;
    s.pc=static_cast<abi::Address>(s.lr)&0xfffffffcu;
    return abi::MemoryCallResult::executed;
}
abi::MemoryCallResult compare_05(abi::GuestCall& s,const abi::GuestMemory& m) noexcept {
    std::uint32_t pointer{},word{};
    if(!m.load_be32(static_cast<abi::Address>(s.gpr[3]),pointer)||!m.load_be32(pointer,word))
        return abi::MemoryCallResult::access_fault;
    s.gpr[11]=0xffffffffc0000000ull;
    s.gpr[10]=0xffffffffc0000005ull;
    s.gpr[9]=pointer;
    s.gpr[8]=word;
    s.gpr[7]=s.gpr[10]-word;
    s.gpr[6]=std::countl_zero(static_cast<std::uint32_t>(s.gpr[7]));
    s.gpr[3]=word==0xc0000005u;
    s.pc=static_cast<abi::Address>(s.lr)&0xfffffffcu;
    return abi::MemoryCallResult::executed;
}
constexpr std::array<abi::MemoryBinding,5> bindings{{
    {0x9219E870u,compare_17},{0x9269CC2Cu,compare_17},{0x926B8084u,compare_17},
    {0x92432DC8u,compare_05},{0x926B56D0u,compare_05}
}};
}
std::span<const abi::MemoryBinding> memory_leaf_bindings_17559() noexcept {return bindings;}
}
