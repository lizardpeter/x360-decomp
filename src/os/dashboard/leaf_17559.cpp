#include "os/dashboard/leaf_17559.hpp"
#include <array>

namespace x360::os::dashboard {
namespace {
// Evidence: all 47 .pdata entries have exactly the same three instructions:
// li r3,1; or r8,r8,r8 (non-recording); blr.
// Only the result register and next instruction address change. No inferred UI semantics.
void return_one(abi::GuestCall& state) noexcept {
    state.gpr[3]=1;
    state.pc=static_cast<abi::Address>(state.lr & ~std::uint64_t{3});
}
constexpr std::array<abi::FunctionBinding,47> bindings{{
    {0x92194CF4u, return_one},
    {0x921961C8u, return_one},
    {0x9219EB14u, return_one},
    {0x922BB928u, return_one},
    {0x9235FE6Cu, return_one},
    {0x923A4620u, return_one},
    {0x923A4930u, return_one},
    {0x923A4D78u, return_one},
    {0x923A4F14u, return_one},
    {0x923A5314u, return_one},
    {0x926742D0u, return_one},
    {0x926FE740u, return_one},
    {0x926FE7ECu, return_one},
    {0x926FE9ECu, return_one},
    {0x926FEA7Cu, return_one},
    {0x926FEB18u, return_one},
    {0x926FEC7Cu, return_one},
    {0x926FED18u, return_one},
    {0x926FED8Cu, return_one},
    {0x926FEDFCu, return_one},
    {0x926FEEE8u, return_one},
    {0x926FEFECu, return_one},
    {0x92704240u, return_one},
    {0x9270424Cu, return_one},
    {0x927047A4u, return_one},
    {0x92705264u, return_one},
    {0x9270570Cu, return_one},
    {0x9273231Cu, return_one},
    {0x92732478u, return_one},
    {0x92732A3Cu, return_one},
    {0x92732AE0u, return_one},
    {0x92732B9Cu, return_one},
    {0x92732E34u, return_one},
    {0x927331DCu, return_one},
    {0x92737314u, return_one},
    {0x927374A0u, return_one},
    {0x9273769Cu, return_one},
    {0x927384E8u, return_one},
    {0x927386B4u, return_one},
    {0x92738780u, return_one},
    {0x927388DCu, return_one},
    {0x927E84A8u, return_one},
    {0x927E8790u, return_one},
    {0x927E8858u, return_one},
    {0x927E8AA0u, return_one},
    {0x927E8D4Cu, return_one},
    {0x92812D9Cu, return_one},
}};
}
std::span<const abi::FunctionBinding> leaf_bindings_17559() noexcept { return bindings; }
}
