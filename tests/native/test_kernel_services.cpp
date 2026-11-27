#include "host/kernel_startup.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360;
using abi::ImportCallResult;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
int main(){
    machine::AddressSpace m;
    host::KernelStartup k;
    std::array<std::uint8_t,24> header{0x58,0x45,0x58,0x32};header[11]=24;
    check(k.install(m,header,0x80001000,0x80002000),"startup");
    std::array<std::uint8_t,128> bytes{};check(m.map(0x1000,bytes,true),"args");
    auto get=[&](std::uint32_t a){std::uint32_t n{};check(m.load_be32(a,n),"load");return n;};
    auto call=[&](std::uint16_t o,std::initializer_list<std::uint32_t> args){
        abi::GuestCall s{};unsigned i=3;for(auto n:args)s.gpr[i++]=n;
        auto r=k.call("xboxkrnl.exe",o,s,m);return std::pair{r,static_cast<std::uint32_t>(s.gpr[3])};
    };
    check(call(0xd1,{0x1000,0,0,0}).first==ImportCallResult::unsupported,"opt in");
    k.enable_kernel_services(m);
    auto ok=[&](std::uint16_t o,std::initializer_list<std::uint32_t> args){
        check(call(o,args)==std::pair{ImportCallResult::completed,0u},"successful service");
    };
    ok(0xd1,{0x1000,0,1,0});auto event=get(0x1000);
    ok(0xd5,{0x1004,0,1,3});auto sem=get(0x1004);
    check(event!=sem&&event&&sem,"unique handles");
    ok(0xda,{event,0x1008,0});auto alias=get(0x1008);
    ok(0xf6,{alias,0x1010});check(get(0x1010)==0,"initial event state");
    ok(0xe6,{event,0x1010});check(get(0x1010)==1&&get(0x1014)==1,"query through alias");
    ok(0xfd,{event,0,0,0});check(call(0xfd,{alias,0,0,0x1060}).second==0x102,"auto event consumed");
    ok(0xcf,{event});check(call(0xcf,{event}).second==0xc0000008,"stale handle");
    ok(0xf6,{alias,0});ok(0xf3,{sem,1,0x1010});check(get(0x1010)==1,"release previous count");
    check(call(0xf3,{sem,2,0}).second==0xc0000047,"semaphore overflow");
    check(m.store_be32(0x1020,alias)&&m.store_be32(0x1024,sem),"wait array");
    ok(0xfe,{2,0x1020,0,0,0,0x1060});
    check(call(0xfe,{2,0x1020,1,0,0,0x1060}).second==1,"wait any index");
    check(call(0xfe,{2,0x1020,1,0,0,0x1060}).second==0x102,"wait timeout");
    check(call(0xf6,{sem,0}).second==0xc0000024,"type mismatch");
    ok(0xf6,{alias,0});ok(0xe2,{alias,0x1010});check(get(0x1010)==1,"pulse");
    ok(0xf6,{alias,0});ok(0xce,{alias});check(call(0xfd,{alias,0,0,0x1060}).second==0x102,"clear");
    ok(0xda,{alias,0x100c,1});auto moved=get(0x100c);
    check(call(0xcf,{alias}).second==0xc0000008,"duplicate close source");ok(0xcf,{moved});ok(0xcf,{sem});
    check(call(0xd1,{0x2000,0,0,0}).first==ImportCallResult::fault,"unmapped output");
    auto small=call(10,{64,0x41424344});check(small.first==ImportCallResult::completed&&small.second,"small allocation");
    auto p=small.second;check((p&4095)==8&&get(p-4)==0x41424344&&get(p)==0,"small header and zero data");
    check(call(19,{p}).second==64,"pool size");
    check(m.store_be32(p,0x1234),"pool write");check(call(15,{p+4}).first==ImportCallResult::unsupported,"interior free");
    check(call(15,{p}).first==ImportCallResult::completed&&!m.writable_range(p,4),"free");
    check(call(15,{p}).first==ImportCallResult::unsupported,"double free");
    auto large=call(11,{8192,0x42424242,0});check(large.first==ImportCallResult::completed&&large.second&&!(large.second&4095),"large pool");
    check(call(19,{large.second}).second==8192,"large size");
    check(call(15,{large.second}).first==ImportCallResult::completed,"large free");
    auto plain=call(9,{32});check(plain.second&&get(plain.second-4)==0x656e6f4e,"untagged pool");
    check(call(11,{32,0,1}).first==ImportCallResult::unsupported,"unknown pool selector");
    std::cout<<"Title-local kernel handle lifecycle, event and semaphore operations, waits and pool allocations passed\n";
}
