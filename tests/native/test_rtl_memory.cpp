#include "host/rtl_memory.hpp"
#include "machine/address_space.hpp"
#include <cstdlib>
#include <iostream>
#include <random>
using namespace x360;
using abi::ImportCallResult;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
int main(){
    machine::AddressSpace m;
    std::array<std::uint8_t,8192> a{},b{};
    std::mt19937 rng(17559);
    for(std::size_t i=0;i<a.size();++i){a[i]=rng();b[i]=i%3?a[i]:std::uint8_t(a[i]+1);}
    check(m.map(0x10000,a,true)&&m.map(0x20000,b,true),"map buffers");
    auto call=[&](std::uint16_t o,std::uint32_t x,std::uint32_t y,std::uint32_t z){
        abi::GuestCall s{};s.gpr[3]=x;s.gpr[4]=y;s.gpr[5]=z;s.gpr[6]=0x12345678;
        auto result=host::RtlMemory::call(o,s,m);
        check(s.gpr[6]==0x12345678,"nonresult register changed");
        return std::pair{result,s.gpr[3]};
    };
    for(unsigned i=0;i<512;++i){
        auto off=rng()%4096,n=rng()%(8193-off);std::uint32_t expected=0;
        for(unsigned j=off;j<off+n;++j)expected+=a[j]==b[j];
        auto [res,val]=call(0x11a,0x10000+off,0x20000+off,n);
        check(res==ImportCallResult::completed&&val==expected,"byte comparison");
    }
    check(call(0x11a,0x10000,0x20000,8193).first==ImportCallResult::fault,"compare across gap");
    check(call(0x126,0x10000,8192,0x12345678).first==ImportCallResult::completed,"fill");
    check(call(0x11b,0x10000,8192,0x12345678).second==2048,"word matches");
    check(m.store_be32(0x10004,0)&&call(0x11b,0x10000,8192,0x12345678).second==2047,"word nonprefix matches");
    check(call(0x11b,0x10001,4,0).second==0,"unaligned compare");
    check(call(0x126,0x10000,8196,0).first==ImportCallResult::fault,"atomic fill");
    std::uint32_t value{};check(m.load_be32(0x10000,value)&&value==0x12345678,"failed fill preserved bytes");
    const std::array<std::uint8_t,8> ansi{'M','e','t','r','o',0,0,0},wide{0,'X',0,'U',0,'I',0,0};
    check(m.map(0x30000,ansi,false)&&m.map(0x31000,wide,false),"source strings");
    check(call(0x12c,0x20000,0x30000,0).first==ImportCallResult::completed,"init ansi");
    check(m.load_be32(0x20000,value)&&value==0x00050006&&m.load_be32(0x20004,value)&&value==0x30000,"ansi descriptor");
    check(call(0x12d,0x20000,0x31000,0).first==ImportCallResult::completed,"init unicode");
    check(m.load_be32(0x20000,value)&&value==0x00060008&&m.load_be32(0x20004,value)&&value==0x31000,"unicode descriptor");
    check(call(0x12c,0x20000,0x30007,0).first==ImportCallResult::completed&&m.load_be32(0x20000,value)&&value==1,"empty nonnull");
    check(call(0x12c,0x20000,0,0).first==ImportCallResult::completed&&m.load_be32(0x20000,value)&&value==0&&m.load_be32(0x20004,value)&&value==0,"null descriptor");
    check(call(0x12c,0x20000,0x32000,0).first==ImportCallResult::fault,"unmapped string");
    check(m.load_be32(0x20000,value)&&value==0,"fault left descriptor intact");
    std::cout<<"Hosted RTL memory and counted string contracts passed\n";
}
