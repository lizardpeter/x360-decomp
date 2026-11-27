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
namespace {
constexpr std::uint32_t page_size=65536;
bool out_word(machine::AddressSpace& memory,abi::Address address){
    return !(address&3u)&&memory.writable_range(address,4);
}
bool overlaps_word(abi::Address word,abi::Address base,std::uint32_t size){
    return std::uint64_t(word)<std::uint64_t(base)+size&&std::uint64_t(base)<std::uint64_t(word)+4;
}
ImportCallResult status(abi::GuestCall& s,std::uint32_t value){
    s.gpr[3]=value;return ImportCallResult::completed;
}
bool in_arena(const machine::Reservation& r){
    return r.page_size==page_size&&r.base>=VirtualMemory::arena_begin&&
           std::uint64_t(r.base)+r.size<=VirtualMemory::arena_end;
}
}
ImportCallResult VirtualMemory::free(abi::GuestCall& s,abi::GuestMemory& memory){
    if(&memory!=&memory_||static_cast<std::uint32_t>(s.gpr[6])!=0)return ImportCallResult::unsupported;
    const auto type=static_cast<std::uint32_t>(s.gpr[5]);
    if(type!=0x4000&&type!=0x8000)return ImportCallResult::unsupported;
    const auto bp=static_cast<abi::Address>(s.gpr[3]),sp=static_cast<abi::Address>(s.gpr[4]);
    if(bp==sp||!out_word(memory_,bp)||!out_word(memory_,sp))return ImportCallResult::fault;
    std::uint32_t base{},size{};
    if(!memory.load_be32(bp,base)||!memory.load_be32(sp,size))return ImportCallResult::fault;
    auto r=memory_.reservation(base);
    if(!r||!in_arena(*r))return status(s,0xc00000a0u);
    if(type==0x8000){
        // Whole-reservation release only; partial release semantics are not modeled.
        if(size||base!=r->base)return ImportCallResult::unsupported;
        size=r->size;
    }else{
        if(!size)return status(s,0);
        if(base%page_size||size%page_size)return ImportCallResult::unsupported;
        if(std::uint64_t(base)+size>std::uint64_t(r->base)+r->size)return status(s,0xc000000du);
    }
    // Never remove either output word before publishing results.
    if(overlaps_word(bp,base,size)||overlaps_word(sp,base,size))return ImportCallResult::unsupported;
    if(!(type==0x8000?memory_.release(base):memory_.decommit(base,size)))return status(s,0xc0000001u);
    if(!memory.store_be32(bp,base)||!memory.store_be32(sp,size))return ImportCallResult::fault;
    return status(s,0);
}
ImportCallResult VirtualMemory::protect(abi::GuestCall& s,abi::GuestMemory& memory){
    if(&memory!=&memory_||static_cast<std::uint32_t>(s.gpr[7])!=0)return ImportCallResult::unsupported;
    const auto protection=static_cast<std::uint32_t>(s.gpr[5]);
    if(protection!=2&&protection!=4)return ImportCallResult::unsupported;
    const auto bp=static_cast<abi::Address>(s.gpr[3]),sp=static_cast<abi::Address>(s.gpr[4]),
               op=static_cast<abi::Address>(s.gpr[6]);
    if(bp==sp||!out_word(memory_,bp)||!out_word(memory_,sp)||
       (op&&(op==bp||op==sp||!out_word(memory_,op))))return ImportCallResult::fault;
    std::uint32_t base{},size{};
    if(!memory.load_be32(bp,base)||!memory.load_be32(sp,size))return ImportCallResult::fault;
    auto r=memory_.reservation(base);
    if(!r||!in_arena(*r)||!size)return status(s,0xc000000du);
    if(base%page_size||size%page_size)return ImportCallResult::unsupported;
    if(std::uint64_t(base)+size>std::uint64_t(r->base)+r->size)return status(s,0xc000000du);
    if(overlaps_word(bp,base,size)||overlaps_word(sp,base,size)||(op&&overlaps_word(op,base,size)))
        return ImportCallResult::unsupported;
    const auto old=memory_.page_writable(base);
    if(!old||!memory_.protect(base,size,protection==4))return status(s,0xc0000022u);
    if(!memory.store_be32(bp,base)||!memory.store_be32(sp,size)||
       (op&&!memory.store_be32(op,*old?4:2)))return ImportCallResult::fault;
    return status(s,0);
}
}
