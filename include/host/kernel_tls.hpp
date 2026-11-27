#pragma once
#include "abi/import_provider.hpp"
#include <bitset>
#include <map>
namespace x360::host {
// One explicit hosted process, with an allocated-slot bitmap and a distinct
// 256-word TLS bank per registered guest thread identity.
class KernelTls {
public:
    static constexpr unsigned count=256;
    static bool handles(std::uint16_t o) noexcept{return o>=0x152&&o<=0x155;}
    bool add_thread(abi::Address identity);
    bool remove_thread(abi::Address identity);
    abi::ImportCallResult call(std::uint16_t ordinal,abi::Address thread,abi::GuestCall& state);
private:
    std::bitset<count> allocated_;
    std::map<abi::Address,std::array<std::uint32_t,count>> threads_;
};
}
