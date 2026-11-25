#include "host/virtual_memory.hpp"
namespace x360::host {
using abi::ImportCallResult;
ImportCallResult VirtualMemory::allocate(abi::GuestCall& s,abi::GuestMemory& memory){
    if(&memory!=&memory_)return ImportCallResult::unsupported;
    auto flags=static_cast<std::uint32_t>(s.gpr[5]),protect=static_cast<std::uint32_t>(s.gpr[6]);
    constexpr std::uint32_t page=65536,reserve=0x60002000,commit=0x60001000,combined=0x60003000;
    // Explicitly opt-in diagnostic model only: isolate the observed XAM
    // request in a different arena and zero fresh host backing even for
    // NOZERO. Do not assert retail selector or physical memory semantics.
    const auto selector=static_cast<std::uint32_t>(s.gpr[7]);
    const bool experimental=diagnostic_selector2_&&selector==2&&flags==0x60803000;
    if(experimental)flags=combined;
    if((selector!=0&&!experimental)||protect!=4||
       (flags!=reserve&&flags!=commit&&flags!=combined))return ImportCallResult::unsupported;
    auto base_ptr=static_cast<abi::Address>(s.gpr[3]),size_ptr=static_cast<abi::Address>(s.gpr[4]);
    if((base_ptr&3u)||(size_ptr&3u)||base_ptr==size_ptr||!memory_.writable_range(base_ptr,4)||!memory_.writable_range(size_ptr,4))
        return ImportCallResult::fault;
    std::uint32_t requested{},size{};
    if(!memory.load_be32(base_ptr,requested)||!memory.load_be32(size_ptr,size))return ImportCallResult::fault;
    auto status=[&](std::uint32_t code){s.gpr[3]=code;return ImportCallResult::completed;};
    if(!size||size>0x04000000)return status(0xc000000du);
    const auto rounded=(size+page-1)&~(page-1);
    abi::Address address=requested;bool created=false;
    if(flags==reserve||flags==combined){
        if(requested)return ImportCallResult::unsupported; // fixed reservation not observed
        auto result=memory_.reserve_first(experimental?selector2_begin:arena_begin,experimental?selector2_end:arena_end,rounded,page);
        if(!result)return status(0xc0000017u);
        address=*result;created=true;
    }else{
        auto region=memory_.reservation(address);
        if(!region||region->page_size!=page||address%page||address<arena_begin||std::uint64_t(address)+rounded>arena_end)
            return ImportCallResult::unsupported;
    }
    if(flags!=reserve&&!memory_.commit(address,rounded,true)){
        if(created)memory_.release(address);
        return status(0xc0000017u);
    }
    // Output words were validated together and cannot overlap the new
    // mapping. The current host model is single-threaded.
    if(!memory.store_be32(base_ptr,address)||!memory.store_be32(size_ptr,rounded)){
        if(created)memory_.release(address);else memory_.decommit(address,rounded);
        return ImportCallResult::fault;
    }
    return status(0);
}
}
