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
std::uint64_t add_carry(abi::GuestCall& s,std::uint64_t a,std::uint64_t b,bool carry){
    auto sum=a+b;auto result=sum+std::uint64_t(carry);
    bool out=sum<a||result<sum;
    s.xer=(s.xer&~0x20000000u)|(out?0x20000000u:0u);
    return result;
}
std::uint64_t word_mask(unsigned mb,unsigned me){
    // PPC64 word rotation replicates the low word. A wrapped mask includes
    // the high 32 bits, unlike a conventional uint32_t circular mask.
    auto low=~std::uint64_t{0}>>(32+mb);
    auto high=~std::uint64_t{0}<<(31-me);
    return mb<=me?low&high:low|high;
}
bool cr_branch(unsigned bo,std::uint32_t cr,unsigned bi){
    return bo==20||bool(cr&(1u<<(31-bi)))==bool(bo&8);
}
bool cr_only(unsigned bo){return (bo>=4&&bo<=7)||(bo>=12&&bo<=15)||bo==20;}
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
                              abi::GuestCall& s,abi::Address return_address,std::size_t budget,abi::ImportProvider* provider){
    BootstrapResult result;
    auto stop=[&](BootstrapStop reason,abi::Address address,const ImportSlot* slot=nullptr){
        result.stop=reason;result.address=address;
        if(slot){result.ordinal=slot->ordinal;result.library=slot->library;}
        return std::move(result);
    };
    std::size_t transitions=0;
    while(transitions++<budget){
        auto pc=s.pc;
        if(pc==return_address)return stop(BootstrapStop::return_address,pc);
        if(auto i=import_at(m,pc,ImportKind::thunk,4)){
            if(provider&&pc==i->address){
                const auto returned=static_cast<abi::Address>(s.lr)&0xfffffffcu;
                auto outcome=provider->call(i->library,i->ordinal,s,memory);
                if(outcome==abi::ImportCallResult::fault)return stop(BootstrapStop::access_fault,i->address,i);
                if(outcome==abi::ImportCallResult::completed){
                    result.services.push_back({i->address,i->ordinal,i->kind});
                    s.pc=returned;continue;
                }
            }
            return stop(BootstrapStop::import_thunk,i->address,i);
        }
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
        }else if(op==8){
            s.gpr[d]=add_carry(s,~s.gpr[a],static_cast<std::uint64_t>(imm),true);
        }else if(op==12||op==13){
            s.gpr[d]=add_carry(s,s.gpr[a],static_cast<std::uint64_t>(imm),false);
            if(op==13)compare_field(s,0,compare(std::bit_cast<std::int64_t>(s.gpr[d]),std::int64_t{0}));
        }else if(op==7){
            s.gpr[d]=s.gpr[a]*static_cast<std::uint64_t>(imm);
        }else if(op==31&&(xo==246||xo==278)&&!(w&1)){
            // Cache touch hints have no architectural memory or register effect.
        }else if(op==31&&xo==28&&!(w&1)){
            s.gpr[a]=s.gpr[d]&s.gpr[b];
        }else if(op==31&&xo==136&&!(w&1)){
            s.gpr[d]=add_carry(s,~s.gpr[a],s.gpr[b],bool(s.xer&0x20000000u));
        }else if(op==31&&xo==266&&!(w&1)){
            s.gpr[d]=s.gpr[a]+s.gpr[b];
        }else if(op==31&&(xo==0||xo==32)&&!(w&1)){
            unsigned field=(w>>23)&7;bool wide=(w>>21)&1;unsigned condition;
            if(xo==0)condition=compare(wide?std::bit_cast<std::int64_t>(s.gpr[a]):sign_extend(static_cast<std::uint32_t>(s.gpr[a]),32),wide?std::bit_cast<std::int64_t>(s.gpr[b]):sign_extend(static_cast<std::uint32_t>(s.gpr[b]),32));
            else condition=compare(wide?s.gpr[a]:std::uint64_t(static_cast<std::uint32_t>(s.gpr[a])),wide?s.gpr[b]:std::uint64_t(static_cast<std::uint32_t>(s.gpr[b])));
            compare_field(s,field,condition);
        }else if(op==24||op==25){
            s.gpr[a]=s.gpr[d]|(std::uint64_t(w&65535)<<(op==25?16:0));
        }else if(op==31&&xo==444&&!(w&1)){
            s.gpr[a]=s.gpr[d]|s.gpr[b];
        }else if(op==31&&(xo==339||xo==467)&&!(w&1)){
            auto spr=a|(b<<5);std::uint64_t* target=nullptr;
            if(spr==8)target=&s.lr;else if(spr==9)target=&s.ctr;else return unsupported();
            if(xo==339)s.gpr[d]=*target;else *target=s.gpr[d];
        }else if(op==20||op==21){
            unsigned mb=(w>>6)&31,me=(w>>1)&31;
            auto mask=word_mask(mb,me);
            auto v=std::uint64_t(std::rotl(static_cast<std::uint32_t>(s.gpr[d]),static_cast<int>(b)));
            v|=v<<32;
            s.gpr[a]=(v&mask)|(op==20?(s.gpr[a]&~mask):0);
            if(w&1)compare_field(s,0,compare(std::bit_cast<std::int64_t>(s.gpr[a]),std::int64_t{0}));
        }else if(op==32||op==34||op==40||op==42||op==58){
            const bool update=op==58&&(w&3)==1;
            const bool algebraic=op==58&&(w&3)==2;
            if((op==58&&(w&3)==3)||(update&&(!a||a==d)))return unsupported();
            unsigned n=op==32||algebraic?4:op==34?1:op==58?8:2;
            auto ea=static_cast<abi::Address>(reg_base(s,a)+static_cast<std::uint64_t>(op==58?sign_extend(w&65532,16):imm));
            if(auto i=import_at(m,ea,ImportKind::value,n)){
                auto v=provider&&ea==i->address&&n==4&&op==32?provider->value(i->library,i->ordinal):std::nullopt;
                if(!v)return stop(BootstrapStop::import_value,i->address,i);
                s.gpr[d]=*v;result.services.push_back({i->address,i->ordinal,i->kind});s.pc=next;++result.retired;continue;
            }
            std::array<std::uint8_t,8> bytes{};
            if(!memory.read(ea,std::span(bytes).first(n)))return stop(BootstrapStop::access_fault,ea);
            std::uint64_t value=0;for(unsigned i=0;i<n;++i)value=(value<<8)|bytes[i];
            s.gpr[d]=op==42||algebraic?static_cast<std::uint64_t>(sign_extend(static_cast<std::uint32_t>(value),algebraic?32:16)):value;
            if(update)s.gpr[a]=ea;
        }else if(op==36||op==37||op==38||op==44||op==62){
            bool update=op==37||(op==62&&(w&3)==1);
            if((op==62&&(w&3)>1)||(update&&!a))return unsupported();
            unsigned n=op==36||op==37?4:op==38?1:op==44?2:8;
            auto ea=static_cast<abi::Address>(reg_base(s,a)+static_cast<std::uint64_t>(op==62?sign_extend(w&65532,16):imm));
            if(auto i=import_at(m,ea,ImportKind::value,n))return stop(BootstrapStop::import_value,i->address,i);
            std::array<std::uint8_t,8> bytes{};
            for(unsigned i=0;i<n;++i)bytes[n-i-1]=static_cast<std::uint8_t>(s.gpr[d]>>(8*i));
            if(!memory.write(ea,std::span(bytes).first(n)))return stop(BootstrapStop::access_fault,ea);
            if(update)s.gpr[a]=ea;
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
            if(!cr_only(d)&&d!=16)return unsupported();
            bool take=cr_branch(d,s.cr,a);
            if(d==16){--s.ctr;take=static_cast<std::uint32_t>(s.ctr)!=0;}
            if(take){
                auto disp=sign_extend(w&65532,16);
                next=static_cast<abi::Address>((w&2)?disp:std::int64_t(pc)+disp);
            }
            if(w&1)s.lr=pc+4;
        }else if(op==19&&xo==16&&cr_only(d)){
            if(cr_branch(d,s.cr,a))next=static_cast<abi::Address>(s.lr)&0xfffffffcu;
            if(w&1)s.lr=pc+4;
        }else if(w==0x4e800420||w==0x4e800421){
            next=static_cast<abi::Address>(s.ctr)&0xfffffffcu;
            if(w&1)s.lr=pc+4;
        }else return unsupported();
        s.pc=next;++result.retired;
    }
    return stop(BootstrapStop::budget,s.pc);
}
}
