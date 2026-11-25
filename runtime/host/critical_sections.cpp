#include "host/critical_sections.hpp"
#include <algorithm>
namespace x360::host {
using abi::ImportCallResult;
namespace {
using Record=std::array<std::uint8_t,28>;
std::uint32_t word(const Record& b,std::size_t p){
    return (std::uint32_t(b[p])<<24)|(std::uint32_t(b[p+1])<<16)|(std::uint32_t(b[p+2])<<8)|b[p+3];
}
void put(Record& b,std::size_t p,std::uint32_t value){
    for(unsigned i=0;i<4;++i)b[p+i]=static_cast<std::uint8_t>(value>>(24-8*i));
}
bool read_record(const abi::GuestCall& s,abi::GuestMemory& memory,Record& b){
    const auto a=static_cast<abi::Address>(s.gpr[3]);
    return a&&!(a&3u)&&memory.read(a,b);
}
bool write_record(const abi::GuestCall& s,abi::GuestMemory& memory,const Record& b){
    return memory.write(static_cast<abi::Address>(s.gpr[3]),b);
}
bool idle(const Record& b){
    return word(b,16)==0xffffffffu&&word(b,20)==0&&word(b,24)==0;
}
bool uncontended_owned(const Record& b){
    auto depth=word(b,20);
    return word(b,24)&&depth&&depth<=0x7fffffffu&&word(b,16)==depth-1;
}
}
ImportCallResult CriticalSections::initialize(abi::GuestCall& s,abi::GuestMemory& memory,bool spin){
    Record b{};
    if(!read_record(s,memory,b))return ImportCallResult::fault;
    auto count=std::uint64_t(static_cast<std::uint32_t>(s.gpr[4]));
    b[0]=1;b[1]=spin?static_cast<std::uint8_t>(std::min<std::uint64_t>((count+255)/256,255)):0;
    put(b,4,0);put(b,16,0xffffffffu);put(b,20,0);put(b,24,0);
    if(!write_record(s,memory,b))return ImportCallResult::fault;
    if(spin)s.gpr[3]=0;
    return ImportCallResult::completed;
}
ImportCallResult CriticalSections::enter(abi::GuestCall& s,abi::GuestMemory& memory,abi::Address owner,bool try_only){
    if(!owner||(owner&3u))return ImportCallResult::unsupported;
    Record b{};if(!read_record(s,memory,b))return ImportCallResult::fault;
    if(b[0]!=1)return ImportCallResult::unsupported;
    if(idle(b)){
        put(b,16,0);put(b,20,1);put(b,24,owner);
    }else if(uncontended_owned(b)){
        if(word(b,24)!=owner){
            if(try_only){s.gpr[3]=0;return ImportCallResult::completed;}
            return ImportCallResult::unsupported; // requires scheduling
        }
        auto depth=word(b,20);
        if(depth==0x7fffffffu)return ImportCallResult::unsupported;
        put(b,16,depth);put(b,20,depth+1);
    }else return ImportCallResult::unsupported; // waiters or unknown structure
    if(!write_record(s,memory,b))return ImportCallResult::fault;
    if(try_only)s.gpr[3]=1;
    return ImportCallResult::completed;
}
ImportCallResult CriticalSections::leave(abi::GuestCall& s,abi::GuestMemory& memory,abi::Address owner){
    if(!owner||(owner&3u))return ImportCallResult::unsupported;
    Record b{};if(!read_record(s,memory,b))return ImportCallResult::fault;
    if(b[0]!=1||!uncontended_owned(b)||word(b,24)!=owner)return ImportCallResult::unsupported;
    const auto depth=word(b,20);
    put(b,16,depth==1?0xffffffffu:depth-2);
    put(b,20,depth-1);
    if(depth==1)put(b,24,0);
    if(!write_record(s,memory,b))return ImportCallResult::fault;
    return ImportCallResult::completed;
}
}
