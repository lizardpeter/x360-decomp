#include "host/kernel_startup.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360;
using abi::ImportCallResult;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
int main(){
    machine::AddressSpace m;host::KernelStartup k;
    std::array<std::uint8_t,24> header{0x58,0x45,0x58,0x32};header[11]=24;
    check(k.install(m,header,0x80001000,0x80002000),"install");
    std::array<std::uint8_t,1024> bytes{};check(m.map(0x1000,bytes,true),"map");
    k.enable_kernel_services(m);
    auto call=[&](std::uint16_t o,std::initializer_list<std::uint32_t> args){
        abi::GuestCall s{};unsigned i=3;for(auto n:args)s.gpr[i++]=n;
        auto r=k.call("xboxkrnl.exe",o,s,m);return std::pair{r,s.gpr[3]};
    };
    auto get=[&](std::uint32_t p){std::uint32_t n{};check(m.load_be32(p,n),"get");return n;};
    auto put=[&](std::uint32_t p,std::uint32_t n){check(m.store_be32(p,n),"put");};
    auto text=[&](std::uint32_t p,std::string_view s){check(m.write(p,{reinterpret_cast<const std::uint8_t*>(s.data()),s.size()}),"text");};
    auto ok=[&](std::uint16_t o,std::initializer_list<std::uint32_t> args){
        check(call(o,args).first==ImportCallResult::completed,"service");
    };
    text(0x1100,"123456789");check(call(0x27b,{0,0x1100,9}).second==0xcbf43926,"CRC known answer");
    auto prefix=call(0x27b,{0,0x1100,4}).second;
    check(call(0x27b,{static_cast<std::uint32_t>(prefix),0x1104,5}).second==0xcbf43926,"incremental CRC");
    text(0x1110,"AbC");text(0x1120,"aBc");
    check(call(0x11d,{0x1110,0xffff,0x1120,0xffff,1}).second==0,"ASCII folded comparison");
    check(static_cast<std::int32_t>(call(0x11d,{0x1110,3,0x1120,3,0}).second)<0,"case sensitive");
    put(0x1000,4);put(0x1004,0x1130);put(0x1008,0x00030004);put(0x100c,0x1110);
    ok(0x121,{0x1000,0x1008});check(get(0x1000)==0x00030004&&get(0x1130)==0x41624300,"descriptor copy");
    ok(0x121,{0x1000,0});check(get(0x1000)==4,"null source resets length");
    std::array<std::uint8_t,4> narrow{0x41,0xe9,0,0xff};check(m.write(0x1140,narrow),"narrow bytes");
    ok(0x133,{0x1150,8,0x1020,0x1140,4});check(get(0x1150)==0x004100e9&&get(0x1154)==0x000000ff&&get(0x1020)==8,"wide conversion");
    put(0x1150,0x004120ac);
    ok(0x143,{0x1160,4,0x1020,0x1150,8});check(get(0x1160)==0x413f00ff&&get(0x1020)==4,"narrow conversion");
    check(call(0x133,{0x1150,8,0x5000,0x1140,4}).first==ImportCallResult::fault&&get(0x1150)==0x004120ac,"atomic conversion fault");
    put(0x1000,0x00000004);put(0x1004,0x1170);put(0x1008,0x00040004);put(0x100c,0x1150);
    ok(0x122,{0x1000,0x1008});check(get(0x1170)==0x004120ac&&get(0x1000)==0x00040004,"unicode descriptor copy");
    k.time()->set_sample(116444736000000000ull,12345678901ull);
    check(call(0x82,{}).second==12345678901ull&&call(0x83,{}).second==10000000,"clock");
    ok(0x84,{0x1080});
    check(((std::uint64_t(get(0x1080))<<32)|get(0x1084))==116444736000000000ull,"system time");
    ok(0x140,{0x1080,0x1090});check(get(0x1090)==0x07b20001&&get(0x1094)==0x00010000&&get(0x1098)==0&&get(0x109c)==4,"unix epoch fields");
    check(call(0x13f,{0x1090,0x10a0}).second==1&&get(0x10a0)==get(0x1080)&&get(0x10a4)==get(0x1084),"time roundtrip");
    put(0x1090,0x07d00002);put(0x1094,0x001d0017);put(0x1098,0x003b003b);put(0x109c,0x03e70000);
    check(call(0x13f,{0x1090,0x10a0}).second==1,"2000 leap day");
    ok(0x140,{0x10a0,0x10b0});check(get(0x10b0)==get(0x1090)&&get(0x10b4)==get(0x1094)&&get(0x10b8)==get(0x1098),"leap day roundtrip");
    put(0x1090,0x076c0002);check(call(0x13f,{0x1090,0x10a0}).second==0,"1900 nonleap");
    check(call(0x152,{}).first==ImportCallResult::unsupported,"TLS requires current thread");
    k.set_diagnostic_thread(0x7000);
    auto slot=static_cast<std::uint32_t>(call(0x152,{}).second);check(slot==0,"first slot");
    check(call(0x155,{slot,0xabcdef}).second==1&&call(0x154,{slot}).second==0xabcdef,"thread one value");
    k.set_diagnostic_thread(0x8000);check(call(0x154,{slot}).second==0,"independent thread value");
    check(call(0x155,{slot,55}).second==1,"thread two set");
    k.set_diagnostic_thread(0x7000);check(call(0x154,{slot}).second==0xabcdef,"thread one preserved");
    check(call(0x153,{slot}).second==1&&call(0x152,{}).second==slot,"reuse slot");
    k.set_diagnostic_thread(0x8000);check(call(0x154,{slot}).second==0,"reuse clears all thread banks");
    for(unsigned i=1;i<256;++i)check(call(0x152,{}).second==i,"fill bitmap");
    check(call(0x152,{}).second==0xffffffffu,"TLS exhaustion");
    std::cout<<"Native strings, conversions, CRC, UTC time and per-thread TLS contracts passed\n";
}
