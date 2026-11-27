#include "host/kernel_tls.hpp"
namespace x360::host {
using abi::ImportCallResult;
bool KernelTls::add_thread(abi::Address identity){
    return identity&&threads_.try_emplace(identity,std::array<std::uint32_t,count>{}).second;
}
bool KernelTls::remove_thread(abi::Address identity){return threads_.erase(identity)!=0;}
ImportCallResult KernelTls::call(std::uint16_t o,abi::Address identity,abi::GuestCall& s){
    auto thread=threads_.find(identity);
    if(thread==threads_.end()||!handles(o))return ImportCallResult::unsupported;
    auto done=[&](std::uint32_t n){s.gpr[3]=n;return ImportCallResult::completed;};
    auto slot=static_cast<std::uint32_t>(s.gpr[3]);
    if(o==0x152){
        for(unsigned i=0;i<count;++i)if(!allocated_[i]){
            allocated_.set(i);
            for(auto& [id,values]:threads_)values[i]=0;
            return done(i);
        }
        return done(0xffffffffu);
    }
    if(slot>=count||!allocated_[slot])return done(0);
    if(o==0x153){
        allocated_.reset(slot);
        for(auto& [id,values]:threads_)values[slot]=0;
        return done(1);
    }
    if(o==0x154)return done(thread->second[slot]);
    thread->second[slot]=static_cast<std::uint32_t>(s.gpr[4]);return done(1);
}
}
