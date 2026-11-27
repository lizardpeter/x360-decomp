#include "host/kernel_pool.hpp"
namespace x360::host {
using abi::ImportCallResult;
KernelPool::~KernelPool(){for(auto [p,a]:live_)memory_.release(a.base);}
bool KernelPool::handles(std::uint16_t o) noexcept{return o==9||o==10||o==11||o==15||o==19;}
ImportCallResult KernelPool::call(std::uint16_t o,abi::GuestCall& s,abi::GuestMemory& memory){
    if(&memory!=&memory_||!handles(o))return ImportCallResult::unsupported;
    const auto arg=static_cast<std::uint32_t>(s.gpr[3]);
    if(o==15||o==19){
        auto found=live_.find(arg);
        if(found==live_.end())return ImportCallResult::unsupported;
        if(o==19){s.gpr[3]=found->second.size;return ImportCallResult::completed;}
        if(!memory_.release(found->second.base))return ImportCallResult::fault;
        live_.erase(found);return ImportCallResult::completed; // void
    }
    if(o==11&&static_cast<std::uint32_t>(s.gpr[5])!=0)return ImportCallResult::unsupported;
    if(!arg||arg>16u*1024*1024){s.gpr[3]=0;return ImportCallResult::completed;}
    // Use the externally documented 8-byte small allocation header.
    // Separate reservations avoid aliasing unrelated objects on free.
    const auto overhead=arg<=0xfd8?8u:0u;
    const auto rounded=(arg+overhead+4095u)&~4095u;
    auto base=memory_.reserve_first(arena_begin,arena_end,rounded,4096);
    if(!base){s.gpr[3]=0;return ImportCallResult::completed;}
    if(!memory_.commit(*base,rounded,true)){
        memory_.release(*base);s.gpr[3]=0;return ImportCallResult::completed;
    }
    if(overhead){
        const auto tag=o==9?0x656e6f4eu:static_cast<std::uint32_t>(s.gpr[4]);
        const std::array<std::uint8_t,8> bytes{0,0,170,0,std::uint8_t(tag>>24),std::uint8_t(tag>>16),std::uint8_t(tag>>8),std::uint8_t(tag)};
        if(!memory.write(*base,bytes)){memory_.release(*base);return ImportCallResult::fault;}
    }
    const auto p=*base+overhead;live_.emplace(p,Allocation{*base,arg});
    s.gpr[3]=p;return ImportCallResult::completed;
}
}
