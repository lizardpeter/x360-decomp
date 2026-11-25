#include "machine/address_space.hpp"
#include "os/dashboard/memory_leaf_17559.hpp"
#include <bit>
#include <cstdlib>
#include <iostream>
#include <random>
using namespace x360;
static void require(bool b,const char* message){if(!b){std::cerr<<message<<'\n';std::exit(1);}}
static abi::GuestCall reference(abi::GuestCall s,const abi::GuestMemory& m,bool second){
    constexpr std::array<std::uint32_t,9> a{0x3d60c000,0x616b0017,0x81430000,0x814a0000,0x7d6a5850,0x7d6b0034,0x5563dffe,0x7d084378,0x4e800020};
    constexpr std::array<std::uint32_t,9> b{0x3d60c000,0x616a0005,0x81230000,0x81090000,0x7ce85050,0x7ce60034,0x54c3dffe,0x7d084378,0x4e800020};
    for(auto w:second?b:a){
        unsigned op=w>>26,d=(w>>21)&31,r=(w>>16)&31,v=(w>>11)&31;
        if(op==15)s.gpr[d]=(r?s.gpr[r]:0)+static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int16_t>(w))*65536);
        else if(op==24)s.gpr[r]=s.gpr[d]|(w&0xffff);
        else if(op==32){std::uint32_t n{};require(m.load_be32(static_cast<abi::Address>((r?s.gpr[r]:0)+static_cast<std::int16_t>(w)),n),"reference read");s.gpr[d]=n;}
        else if(op==31&&((w>>1)&1023)==40)s.gpr[d]=s.gpr[v]-s.gpr[r];
        else if(op==31&&((w>>1)&1023)==26)s.gpr[r]=std::countl_zero(static_cast<std::uint32_t>(s.gpr[d]));
        else if(op==21){require(((w>>6)&31)==31&&((w>>1)&31)==31,"reference mask");s.gpr[r]=std::rotl(static_cast<std::uint32_t>(s.gpr[d]),int(v))&1u;}
        else if(op==31&&((w>>1)&1023)==444)s.gpr[r]=s.gpr[d]|s.gpr[v];
        else if(w==0x4e800020){s.pc=static_cast<abi::Address>(s.lr)&0xfffffffcu;continue;}
        else require(false,"unknown reference instruction");
        s.pc+=4;
    }
    return s;
}
int main(){
    machine::AddressSpace m;
    const std::array<std::uint8_t,8> zero{};
    require(m.map(0x1000,zero,true),"first region");
    require(m.map(0x2000,zero,true),"second region");
    require(!m.map(0x1004,zero,true),"overlap");
    require(!m.map(0xfffffffc,zero,true),"wrap map");
    require(m.map(0x3000,zero,false),"read-only map");
    require(!m.store_be32(0x3000,1),"readonly write");
    require(m.store_be32(0x1000,0x2000),"pointer store");
    require(m.store_be32(0x2000,0x12345678),"word store");
    std::array<std::uint8_t,4> data{};
    require(m.read(0x2000,data)&&data==std::array<std::uint8_t,4>{0x12,0x34,0x56,0x78},"endian");
    require(!m.store_be32(0x2006,0xffffffff),"partial write accepted");
    std::uint32_t word=7;require(!m.load_be32(0x2006,word)&&word==7,"fault mutated output");
    std::mt19937_64 rng(17559);unsigned cases=0;
    for(auto binding:os::dashboard::memory_leaf_bindings_17559()){
        bool second=binding.address==0x92432dc8u||binding.address==0x926b56d0u;
        for(unsigned i=0;i<512;i++){
            std::uint32_t w=i==0?0xc0000017u:i==1?0xc0000005u:i==2?0u:i==3?0xffffffffu:static_cast<std::uint32_t>(rng());
            require(m.store_be32(0x2000,w),"test word store");
            abi::GuestCall state;for(auto& r:state.gpr)r=rng();state.gpr[3]=0xaabbccdd00001000ull;state.lr=rng();state.ctr=rng();state.cr=rng();state.xer=rng();state.pc=binding.address;
            auto expected=reference(state,m,second);
            require(binding.implementation(state,m)==abi::MemoryCallResult::executed&&state==expected,"native/reference mismatch");
            state.gpr[3]=0x4000;auto before=state;
            require(binding.implementation(state,m)==abi::MemoryCallResult::access_fault&&state==before,"fault contract");
            ++cases;
        }
    }
    std::cout<<cases<<" memory-backed native/reference cases passed\n";
}
