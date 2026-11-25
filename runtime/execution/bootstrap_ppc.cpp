#include "execution/bootstrap_ppc.hpp"
#include <algorithm>
#include <bit>
#include <cstdint>

namespace x360::execution {
namespace {
constexpr std::int64_t sign_extend(std::uint32_t v,unsigned bits){
    const auto sign=std::uint64_t{1}<<(bits-1);
    return (v&sign)?std::int64_t(v)-std::int64_t(sign*2):std::int64_t(v);
}
std::uint64_t reg_base(const abi::GuestCall& s,unsigned a){return a?s.gpr[a]:0;}
const ImportSlot* import_at(const ModuleManifest& m,abi::Address a,ImportKind kind,unsigned bytes){
    // The registry validates all import extents; do not interpret unpatched
    // value words as addresses or thunk placeholders as instructions.
    const auto end=std::uint64_t(a)+bytes;
    for(auto& i:m.imports)if(i.kind==kind&&std::uint64_t(i.address)<end&&std::uint64_t(i.address)+4>a)return &i;
    return nullptr;
}
void compare_field(abi::GuestCall& s,unsigned field,unsigned value){
    unsigned shift=28-4*field;
    value|=(s.xer>>31)&1;
    s.cr=(s.cr&~(15u<<shift))|(value<<shift);
}
template<class T>unsigned compare(T a,T b){return a<b?8:a>b?4:2;}
}
BootstrapResult bootstrap_ppc(const ModuleManifest& m,abi::GuestMemory& memory,
                              abi::GuestCall& s,abi::Address return_address,std::size_t budget){
    BootstrapResult result;
    auto stop=[&](BootstrapStop reason,abi::Address address,const ImportSlot* slot=nullptr){
        result.stop=reason;result.address=address;
        if(slot){result.ordinal=slot->ordinal;result.library=slot->library;}
        return std::move(result);
    };
    while(result.retired<budget){
        auto pc=s.pc;
        if(pc==return_address)return stop(BootstrapStop::return_address,pc);
        if(auto i=import_at(m,pc,ImportKind::thunk,4))return stop(BootstrapStop::import_thunk,i->address,i);
        if(!ModuleRegistry::executable(m,pc))return stop(BootstrapStop::non_executable,pc);
        std::uint32_t w{};
        if(!memory.load_be32(pc,w))return stop(BootstrapStop::access_fault,pc);
        result.trace.push_back({pc,w});
        unsigned op=w>>26,d=(w>>21)&31,a=(w>>16)&31,b=(w>>11)&31,xo=(w>>1)&1023;
        auto imm=sign_extend(w&65535,16);
        auto next=pc+4;
        auto unsupported=[&](){return stop(BootstrapStop::unsupported_instruction,pc);};
        // Decode before modifying state. Memory reads and writes have the
        // checked provider contract; any unhandled instruction stops.
        if(op==14||op==15){
            s.gpr[d]=reg_base(s,a)+static_cast<std::uint64_t>(imm*(op==15?65536:1));
        }else if(op==24||op==25){
            s.gpr[a]=s.gpr[d]|(std::uint64_t(w&65535)<<(op==25?16:0));
        }else if(op==31&&xo==444&&!(w&1)){
            s.gpr[a]=s.gpr[d]|s.gpr[b];
        }else if(op==31&&(xo==339||xo==467)&&!(w&1)){
            auto spr=a|(b<<5);std::uint64_t* target=nullptr;
            if(spr==8)target=&s.lr;else if(spr==9)target=&s.ctr;else return unsupported();
            if(xo==339)s.gpr[d]=*target;else *target=s.gpr[d];
        }else if(op==21){
            unsigned mb=(w>>6)&31,me=(w>>1)&31;
            if(mb>me)return unsupported(); // wrap masks deliberately not implemented
            auto mask=static_cast<std::uint32_t>(((std::uint64_t{1}<<(me-mb+1))-1)<<(31-me));
            s.gpr[a]=std::rotl(static_cast<std::uint32_t>(s.gpr[d]),static_cast<int>(b))&mask;
            if(w&1)compare_field(s,0,compare(s.gpr[a],std::uint64_t{0}));
        }else if(op==32||op==34||op==40||op==42||op==58){
            if(op==58&&(w&3))return unsupported();
            unsigned n=op==32?4:op==34?1:op==58?8:2;
            auto ea=static_cast<abi::Address>(reg_base(s,a)+static_cast<std::uint64_t>(op==58?sign_extend(w&65532,16):imm));
            if(auto i=import_at(m,ea,ImportKind::value,n))return stop(BootstrapStop::import_value,i->address,i);
            std::array<std::uint8_t,8> bytes{};
            if(!memory.read(ea,std::span(bytes).first(n)))return stop(BootstrapStop::access_fault,ea);
            std::uint64_t value=0;for(unsigned i=0;i<n;++i)value=(value<<8)|bytes[i];
            s.gpr[d]=op==42?static_cast<std::uint64_t>(sign_extend(static_cast<std::uint32_t>(value),16)):value;
        }else if(op==36||op==37||op==38||op==44||op==62){
            if((op==62&&(w&3))||(op==37&&!a))return unsupported();
            unsigned n=op==36||op==37?4:op==38?1:op==44?2:8;
            auto ea=static_cast<abi::Address>(reg_base(s,a)+static_cast<std::uint64_t>(op==62?sign_extend(w&65532,16):imm));
            if(auto i=import_at(m,ea,ImportKind::value,n))return stop(BootstrapStop::import_value,i->address,i);
            std::array<std::uint8_t,8> bytes{};
            for(unsigned i=0;i<n;++i)bytes[n-i-1]=static_cast<std::uint8_t>(s.gpr[d]>>(8*i));
            if(!memory.write(ea,std::span(bytes).first(n)))return stop(BootstrapStop::access_fault,ea);
            if(op==37)s.gpr[a]=ea;
        }else if(op==10||op==11){
            unsigned field=(w>>23)&7;
            bool wide=(w>>21)&1;
            unsigned condition;
            if(op==10)condition=compare(wide?s.gpr[a]:std::uint64_t(static_cast<std::uint32_t>(s.gpr[a])),std::uint64_t(w&65535));
            else condition=compare(wide?std::bit_cast<std::int64_t>(s.gpr[a]):sign_extend(static_cast<std::uint32_t>(s.gpr[a]),32),imm);
            compare_field(s,field,condition);
        }else if(op==18){
            auto disp=sign_extend(w&0x03fffffc,26);
            next=static_cast<abi::Address>((w&2)?disp:std::int64_t(pc)+disp);
            if(w&1)s.lr=pc+4;
        }else if(op==16){
            if(d!=4&&d!=12&&d!=20)return unsupported();
            bool take=d==20||bool(s.cr&(1u<<(31-a)))==(d==12);
            if(take){
                auto disp=sign_extend(w&65532,16);
                next=static_cast<abi::Address>((w&2)?disp:std::int64_t(pc)+disp);
            }
            if(w&1)s.lr=pc+4;
        }else if(w==0x4e800020){
            next=static_cast<abi::Address>(s.lr)&0xfffffffcu;
        }else if(w==0x4e800420||w==0x4e800421){
            next=static_cast<abi::Address>(s.ctr)&0xfffffffcu;
            if(w&1)s.lr=pc+4;
        }else return unsupported();
        s.pc=next;++result.retired;
    }
    return stop(BootstrapStop::budget,s.pc);
}
}
