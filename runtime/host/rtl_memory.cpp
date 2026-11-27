#include "host/rtl_memory.hpp"
#include <algorithm>
#include <vector>
namespace x360::host {
using abi::ImportCallResult;
namespace {
constexpr std::uint32_t max_transfer=16*1024*1024;
bool range(abi::Address a,std::uint32_t n){
    return std::uint64_t(a)+n<=0x100000000ull;
}
std::uint32_t word(std::span<const std::uint8_t> b,std::size_t at){
    return (std::uint32_t(b[at])<<24)|(std::uint32_t(b[at+1])<<16)|
           (std::uint32_t(b[at+2])<<8)|b[at+3];
}
ImportCallResult done(abi::GuestCall& s,std::uint32_t value){
    s.gpr[3]=value;return ImportCallResult::completed;
}
}
ImportCallResult RtlMemory::call(std::uint16_t ordinal,abi::GuestCall& s,abi::GuestMemory& memory){
    const auto a=static_cast<abi::Address>(s.gpr[3]);
    if(ordinal==0x11a){
        const auto b=static_cast<abi::Address>(s.gpr[4]),n=static_cast<std::uint32_t>(s.gpr[5]);
        if(n>max_transfer)return ImportCallResult::unsupported;
        if(!range(a,n)||!range(b,n))return ImportCallResult::fault;
        if(!n)return done(s,0);
        // Count equal positions, including matches following a mismatch.
        std::array<std::uint8_t,4096> left{},right{};
        std::uint32_t count=0;
        for(std::uint32_t off=0;off<n;){
            const auto len=std::min<std::uint32_t>(left.size(),n-off);
            if(!memory.read(a+off,std::span(left).first(len))||
               !memory.read(b+off,std::span(right).first(len)))return ImportCallResult::fault;
            for(std::uint32_t j=0;j<len;++j)count+=left[j]==right[j];
            off+=len;
        }
        return done(s,count);
    }
    if(ordinal==0x11b||ordinal==0x126){
        const auto n=static_cast<std::uint32_t>(s.gpr[4]),pattern=static_cast<std::uint32_t>(s.gpr[5]);
        if((a&3u)||(n&3u)){
            if(ordinal==0x11b)return done(s,0);
            return ImportCallResult::unsupported;
        }
        if(n>max_transfer)return ImportCallResult::unsupported;
        if(!range(a,n))return ImportCallResult::fault;
        if(!n)return ordinal==0x11b?done(s,0):ImportCallResult::completed;
        if(ordinal==0x11b){
            std::array<std::uint8_t,4096> block{};
            std::uint32_t count=0;
            for(std::uint32_t off=0;off<n;){
                const auto len=std::min<std::uint32_t>(block.size(),n-off);
                if(!memory.read(a+off,std::span(block).first(len)))return ImportCallResult::fault;
                for(std::uint32_t j=0;j<len;j+=4)count+=word(block,j)==pattern;
                off+=len;
            }
            return done(s,count);
        }
        // A single atomic guest-memory write avoids partially modifying a
        // destination spanning a hole or a protected region.
        std::vector<std::uint8_t> bytes(n);
        for(std::uint32_t i=0;i<n;i+=4)
            for(unsigned j=0;j<4;++j)bytes[i+j]=static_cast<std::uint8_t>(pattern>>(24-8*j));
        return memory.write(a,bytes)?ImportCallResult::completed:ImportCallResult::fault;
    }
    if(ordinal==0x12c||ordinal==0x12d){
        const auto source=static_cast<abi::Address>(s.gpr[4]);
        const std::uint32_t unit=ordinal==0x12d?2:1;
        if(!a||(a&3u)||!range(a,8)||(source&&source%unit))return ImportCallResult::fault;
        std::uint32_t len=0;
        if(source){
            // The 16-bit descriptor stores lengths in bytes, including
            // room for a terminator in MaximumLength. No truncation/wrap.
            for(;;){
                if(len>65535-unit||!range(source,std::uint32_t(len+unit)))return ImportCallResult::unsupported;
                std::array<std::uint8_t,2> chars{};
                if(!memory.read(source+len,std::span(chars).first(unit)))return ImportCallResult::fault;
                if(chars[0]==0&&chars[1]==0)break;
                len+=unit;
            }
        }
        const auto cap=source?len+unit:0u;
        const std::array<std::uint8_t,8> descriptor{
            std::uint8_t(len>>8),std::uint8_t(len),std::uint8_t(cap>>8),std::uint8_t(cap),
            std::uint8_t(source>>24),std::uint8_t(source>>16),std::uint8_t(source>>8),std::uint8_t(source)};
        return memory.write(a,descriptor)?ImportCallResult::completed:ImportCallResult::fault;
    }
    return ImportCallResult::unsupported;
}
}
