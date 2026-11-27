#include "host/dispatcher_objects.hpp"
#include "machine/address_space.hpp"
#include <algorithm>
namespace x360::host {
using abi::ImportCallResult;
namespace {
using Record=std::array<std::uint8_t,20>;
std::uint32_t word(const Record& b,unsigned at){
    return (std::uint32_t(b[at])<<24)|(std::uint32_t(b[at+1])<<16)|
           (std::uint32_t(b[at+2])<<8)|b[at+3];
}
void put(Record& b,unsigned at,std::uint32_t n){
    for(unsigned j=0;j<4;++j)b[at+j]=static_cast<std::uint8_t>(n>>(24-8*j));
}
ImportCallResult done(abi::GuestCall& s,std::uint32_t value){
    s.gpr[3]=value;return ImportCallResult::completed;
}
bool empty_waitlist(const Record& b,abi::Address address){
    return word(b,8)==address+8&&word(b,12)==address+8;
}
// KeWaitForMultipleObjects: only the immediate single-threaded path.
// Validate the complete set before consuming any auto-reset event/semaphore.
ImportCallResult wait_multiple(abi::GuestCall& s,abi::GuestMemory& memory){
    const auto count=static_cast<std::uint32_t>(s.gpr[3]);
    const auto objects=static_cast<abi::Address>(s.gpr[4]);
    const auto kind=static_cast<std::uint32_t>(s.gpr[5]); // WaitAll=0, WaitAny=1
    const auto mode=static_cast<std::uint32_t>(s.gpr[7]);
    const auto alertable=static_cast<std::uint32_t>(s.gpr[8]);
    const auto timeout=static_cast<abi::Address>(s.gpr[9]);
    if(!count||count>64||kind>1||mode>1||alertable)return ImportCallResult::unsupported;
    if(!objects||(objects&3u)||std::uint64_t(objects)+count*4>0x100000000ull)return ImportCallResult::fault;
    bool poll=false;
    if(timeout){
        std::array<std::uint8_t,8> b{};
        if((timeout&7u)||!memory.read(timeout,b))return ImportCallResult::fault;
        poll=std::all_of(b.begin(),b.end(),[](auto x){return x==0;});
    }
    struct Item{abi::Address address;std::uint32_t signal;bool consume;};
    std::array<Item,64> items{};
    unsigned first=count;
    bool all=true;
    for(unsigned i=0;i<count;++i){
        abi::Address address{};
        if(!memory.load_be32(objects+4*i,address)||!address||(address&3u)||address>0xffffffecu)
            return ImportCallResult::fault;
        // Duplicate or overlapping guest object records are not a valid
        // independent wait set in this restricted model.
        for(unsigned j=0;j<i;++j){
            const auto prior=items[j].address;
            if(std::uint64_t(address)<std::uint64_t(prior)+20&&
               std::uint64_t(prior)<std::uint64_t(address)+20)return ImportCallResult::unsupported;
        }
        Record record{};
        if(!memory.read(address,std::span(record).first(16)))return ImportCallResult::fault;
        if(!empty_waitlist(record,address))return ImportCallResult::unsupported;
        const auto signal=word(record,4);
        if(record[0]<=1){
            if(signal>1)return ImportCallResult::unsupported;
        }else if(record[0]==5){
            if(!memory.read(address+16,std::span(record).subspan(16,4)))return ImportCallResult::fault;
            const auto limit=word(record,16);
            if(!limit||limit>0x7fffffffu||signal>limit)return ImportCallResult::unsupported;
        }else return ImportCallResult::unsupported;
        items[i]={address,signal,record[0]!=0};
        if(signal&&first==count)first=i;
        all=all&&signal!=0;
    }
    if((kind==0&&!all)||(kind==1&&first==count))
        return poll?done(s,0x102):ImportCallResult::unsupported;
    // Only the AddressSpace provider guarantees validated writes remain
    // valid throughout this single-threaded transaction.
    auto* space=dynamic_cast<machine::AddressSpace*>(&memory);
    if(!space)return ImportCallResult::unsupported;
    for(unsigned i=0;i<count;++i)
        if((kind==0||i==first)&&items[i].consume&&!space->writable_range(items[i].address+4,4))
            return ImportCallResult::fault;
    for(unsigned i=0;i<count;++i)
        if((kind==0||i==first)&&items[i].consume)
            if(!memory.store_be32(items[i].address+4,items[i].signal-1))return ImportCallResult::fault;
    return done(s,kind==0?0:first);
}
}
ImportCallResult DispatcherObjects::call(std::uint16_t ordinal,abi::GuestCall& s,abi::GuestMemory& memory){
    if(ordinal==0xaf)return wait_multiple(s,memory);
    const auto a=static_cast<abi::Address>(s.gpr[3]);
    if(!a||(a&3u)||a>0xffffffecu)return ImportCallResult::fault;
    Record record{};
    if(ordinal==0x70||ordinal==0x74){
        const auto x=static_cast<std::uint32_t>(s.gpr[4]),y=static_cast<std::uint32_t>(s.gpr[5]);
        if(ordinal==0x70){
            if(x>1||y>1)return ImportCallResult::unsupported;
            record[0]=static_cast<std::uint8_t>(x);put(record,4,y);
        }else{
            if(!y||y>0x7fffffffu||x>y)return ImportCallResult::unsupported;
            record[0]=5;put(record,4,x);put(record,16,y);
        }
        put(record,8,a+8);put(record,12,a+8);
        const auto n=ordinal==0x70?16u:20u;
        return memory.write(a,std::span(record).first(n))?ImportCallResult::completed:ImportCallResult::fault;
    }
    if(ordinal!=0x8f&&ordinal!=0x9d&&ordinal!=0x88&&ordinal!=0xb0&&ordinal!=0x7f)return ImportCallResult::unsupported;
    if(!memory.read(a,std::span(record).first(16)))return ImportCallResult::fault;
    if(!empty_waitlist(record,a))return ImportCallResult::unsupported;
    const bool event=record[0]<=1,semaphore=record[0]==5;
    if(!event&&!semaphore)return ImportCallResult::unsupported;
    const auto previous=word(record,4);
    std::uint32_t next=previous;
    if(event&&previous>1)return ImportCallResult::unsupported;
    if(semaphore){
        if(!memory.read(a+16,std::span(record).subspan(16,4)))return ImportCallResult::fault;
        const auto limit=word(record,16);
        if(!limit||limit>0x7fffffffu||previous>limit)return ImportCallResult::unsupported;
    }
    switch(ordinal){
        case 0x7f:
            if(static_cast<std::uint32_t>(s.gpr[5])!=0)return ImportCallResult::unsupported;
            [[fallthrough]];
        case 0x8f:
            if(!event)return ImportCallResult::unsupported;
            next=0;break;
        case 0x9d:
            if(!event||static_cast<std::uint32_t>(s.gpr[5])!=0)return ImportCallResult::unsupported;
            next=1;break;
        case 0x88:{
            if(!semaphore||static_cast<std::uint32_t>(s.gpr[6])!=0)return ImportCallResult::unsupported;
            const auto adjustment=static_cast<std::uint32_t>(s.gpr[5]);
            if(!adjustment||adjustment>word(record,16)-previous)return ImportCallResult::unsupported;
            next=previous+adjustment;break;
        }
        case 0xb0:{
            // No APC delivery or sleeping is represented. A zero timeout
            // permits an unsuccessful poll. Positive/infinite waits that
            // cannot complete immediately remain unsupported.
            if(static_cast<std::uint32_t>(s.gpr[6])!=0||
               static_cast<std::uint32_t>(s.gpr[5])>1)return ImportCallResult::unsupported;
            const auto timeout=static_cast<abi::Address>(s.gpr[7]);
            bool poll=false;
            if(timeout){
                std::array<std::uint8_t,8> b{};
                if((timeout&7u)||!memory.read(timeout,b))return ImportCallResult::fault;
                poll=true;for(auto n:b)if(n)poll=false;
            }
            if(!previous)return poll?done(s,0x102):ImportCallResult::unsupported;
            if(semaphore||record[0]==1)next=previous-1;
            if(next!=previous&&!memory.store_be32(a+4,next))return ImportCallResult::fault;
            return done(s,0);
        }
    }
    if(next!=previous&&!memory.store_be32(a+4,next))return ImportCallResult::fault;
    return done(s,previous);
}
}
