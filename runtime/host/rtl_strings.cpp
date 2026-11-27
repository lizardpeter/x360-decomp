#include "host/rtl_strings.hpp"
#include "machine/address_space.hpp"
#include <algorithm>
#include <array>
#include <vector>
namespace x360::host {
using abi::ImportCallResult;
namespace {
constexpr std::uint32_t max_transfer=16u*1024*1024;
std::uint32_t arg(const abi::GuestCall& s,unsigned n){return static_cast<std::uint32_t>(s.gpr[3+n]);}
ImportCallResult done(abi::GuestCall& s,std::uint32_t result){s.gpr[3]=result;return ImportCallResult::completed;}
bool fits(abi::Address p,std::size_t n){return std::uint64_t(p)+n<=0x100000000ull;}
bool overlaps(abi::Address a,std::size_t n,abi::Address b,std::size_t m){
    return n&&m&&std::uint64_t(a)<std::uint64_t(b)+m&&std::uint64_t(b)<std::uint64_t(a)+n;
}
std::uint32_t unit(std::span<const std::uint8_t> b,unsigned offset,unsigned width){
    return width==1?b[offset]:(std::uint32_t(b[offset])<<8)|b[offset+1];
}
std::uint32_t lower(std::uint32_t c){return c>='A'&&c<='Z'?c+32:c;}
struct Descriptor{std::uint32_t length{},capacity{};abi::Address pointer{};};
bool descriptor(abi::GuestMemory& m,abi::Address p,Descriptor& d,unsigned width){
    std::uint32_t n{},ptr{};
    if(!p||(p&3u)||!fits(p,8)||!m.load_be32(p,n)||!m.load_be32(p+4,ptr))return false;
    d={n>>16,n&65535u,ptr};
    return d.length<=d.capacity&&d.length%width==0&&d.capacity%width==0&&
           (!d.capacity||d.pointer)&&d.pointer%width==0&&fits(d.pointer,d.capacity);
}
bool can_write(machine::AddressSpace& m,abi::Address at,std::size_t n){return !n||(at&&m.writable_range(at,n));}
bool scan(abi::GuestMemory& m,abi::Address p,std::uint32_t& n){
    if(n!=0xffffu)return n<=max_transfer&&fits(p,n);
    for(n=0;n<max_transfer;++n){
        if(!fits(p,n+1))return false;
        std::array<std::uint8_t,1> byte{};if(!m.read(p+n,byte))return false;
        if(!byte[0])return true;
    }
    return false;
}
}
bool RtlStrings::handles(std::uint16_t o) noexcept{
    switch(o){case 0x11d:case 0x121:case 0x122:case 0x133:case 0x134:
    case 0x143:case 0x144:case 0x27b:return true;default:return false;}
}
ImportCallResult RtlStrings::call(std::uint16_t o,abi::GuestCall& s,abi::GuestMemory& m){
    const auto a=arg(s,0),b=arg(s,1),c=arg(s,2),d=arg(s,3),e=arg(s,4);
    if(o==0x11d){
        auto n1=b,n2=d;
        if(e>1)return ImportCallResult::unsupported;
        if(!scan(m,a,n1)||!scan(m,c,n2))return ImportCallResult::fault;
        const auto n=std::min(n1,n2);
        // Bounded strncmp-style compare of the common range. Do not read
        // beyond the first NUL or silently apply a host locale to guest bytes.
        for(unsigned i=0;i<n;++i){
            std::array<std::uint8_t,1> x{},y{};
            if(!m.read(a+i,x)||!m.read(c+i,y))return ImportCallResult::fault;
            if(e&&(x[0]>127||y[0]>127))return ImportCallResult::unsupported;
            const auto l=e?lower(x[0]):x[0],r=e?lower(y[0]):y[0];
            if(l!=r)return done(s,l-r);
            if(!l)return done(s,0);
        }
        return done(s,0);
    }
    if(o==0x121||o==0x122){
        auto* space=dynamic_cast<machine::AddressSpace*>(&m);if(!space)return ImportCallResult::unsupported;
        unsigned width=o==0x122?2:1;Descriptor dest{},src{};
        if(!descriptor(m,a,dest,width)||(b&&!descriptor(m,b,src,width)))return ImportCallResult::fault;
        const auto n=b?std::min(dest.capacity,src.length):0u;
        if(!can_write(*space,a,4)||!can_write(*space,dest.pointer,n)||overlaps(a,8,dest.pointer,n))
            return ImportCallResult::fault;
        std::vector<std::uint8_t> bytes(n);
        if(n&&!m.read(src.pointer,bytes))return ImportCallResult::fault;
        if(n&&!m.write(dest.pointer,bytes))return ImportCallResult::fault;
        if(!m.store_be32(a,(n<<16)|dest.capacity))return ImportCallResult::fault;
        return ImportCallResult::completed;
    }
    if(o==0x133||o==0x143){
        auto* space=dynamic_cast<machine::AddressSpace*>(&m);if(!space)return ImportCallResult::unsupported;
        const bool wide=o==0x133;
        const auto n=wide?std::min(b/2,e):std::min(b,e/2);
        const auto input_bytes=n*(wide?1:2),output_bytes=n*(wide?2:1);
        if(input_bytes>max_transfer||output_bytes>max_transfer)return ImportCallResult::unsupported;
        if(!fits(d,input_bytes)||!can_write(*space,a,output_bytes)||
           (wide&&(a&1u))||(!wide&&(d&1u))||(c&&((c&3u)||!can_write(*space,c,4)))||
           overlaps(a,output_bytes,c,c?4:0))return ImportCallResult::fault;
        std::vector<std::uint8_t> input(input_bytes),out(output_bytes);
        if(input_bytes&&!m.read(d,input))return ImportCallResult::fault;
        for(unsigned i=0;i<n;++i){
            auto value=unit(input,i*(wide?1:2),wide?1:2);
            if(wide){out[2*i]=0;out[2*i+1]=static_cast<std::uint8_t>(value);}
            else out[i]=value<256?static_cast<std::uint8_t>(value):static_cast<std::uint8_t>('?');
        }
        if(output_bytes&&!m.write(a,out))return ImportCallResult::fault;
        if(c&&!m.store_be32(c,output_bytes))return ImportCallResult::fault;
        return done(s,0);
    }
    if(o==0x134||o==0x144){
        if(o==0x134&&c>0x7fffffffu)return ImportCallResult::unsupported;
        if(a&&((a&3u)||!m.store_be32(a,o==0x134?c*2:c/2)))return ImportCallResult::fault;
        return done(s,0);
    }
    if(o==0x27b){
        if(c>max_transfer)return ImportCallResult::unsupported;
        if(!fits(b,c))return ImportCallResult::fault;
        // IEEE reflected CRC-32, incremental seed semantics. Generate the
        // small lookup table at compile time rather than copying a table.
        static constexpr auto table=[]{
            std::array<std::uint32_t,256> t{};
            for(unsigned i=0;i<t.size();++i){
                auto x=i;for(unsigned j=0;j<8;++j)x=(x>>1)^((x&1)?0xedb88320u:0u);
                t[i]=x;
            }
            return t;
        }();
        std::uint32_t crc=~a;std::array<std::uint8_t,4096> buffer{};
        for(unsigned off=0;off<c;){
            auto n=std::min<std::uint32_t>(buffer.size(),c-off);
            if(!m.read(b+off,std::span(buffer).first(n)))return ImportCallResult::fault;
            for(unsigned i=0;i<n;++i)crc=table[(crc^buffer[i])&255]^(crc>>8);
            off+=n;
        }
        return done(s,~crc);
    }
    return ImportCallResult::unsupported;
}
}
