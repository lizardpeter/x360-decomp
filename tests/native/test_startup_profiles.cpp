#include "host/kernel_startup.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360;
using abi::ImportCallResult;
static void check(bool b,const char* msg){if(!b){std::cerr<<msg<<'\n';std::exit(1);}}
int main(){
    machine::AddressSpace m;host::KernelStartup k;
    std::array<std::uint8_t,24> header{'X','E','X','2',0,0,0,0,0,0,0,24};
    std::array<std::uint8_t,16> hardware{0,0,0,0x20,6};
    check(!k.install_hardware_info(m,hardware),"must install loader first");
    check(k.install(m,header,0x80001000,0x80002000),"loader");
    check(!k.value("xboxkrnl.exe",342),"no default hardware");
    check(!k.install_hardware_info(m,{}),"zero CPU count");
    check(k.install_hardware_info(m,hardware),"hardware profile");
    check(!k.install_hardware_info(m,hardware),"double install");
    check(k.value("xboxkrnl.exe",342)==host::KernelStartup::hardware_info_address,"value import");
    std::array<std::uint8_t,16> read{};
    check(m.read(host::KernelStartup::hardware_info_address,read)&&read==hardware,"exact profile bytes");
    check(!m.store_be32(host::KernelStartup::hardware_info_address,0),"readonly");
    abi::GuestCall s;s.gpr[3]=10;auto before=s;
    check(k.call("xboxkrnl.exe",404,s,m)==ImportCallResult::unsupported&&s==before,"privilege check stays unresolved");
    std::array<std::uint8_t,16> params{};check(m.map(0x1000,params,true),"params");
    s.gpr[3]=0x1000;s.gpr[4]=0x1004;s.gpr[5]=0x60803000;s.gpr[6]=4;s.gpr[7]=2;
    check(m.store_be32(0x1004,0x10001),"size");
    k.enable_virtual_memory(m);before=s;
    check(k.call("xboxkrnl.exe",204,s,m)==ImportCallResult::unsupported&&s==before,"strict selector rejection");
    k.enable_virtual_memory(m,true);
    check(k.call("xboxkrnl.exe",204,s,m)==ImportCallResult::completed&&!s.gpr[3],"opt-in diagnostic allocation");
    std::uint32_t base{},size{},word=1;
    check(m.load_be32(0x1000,base)&&base==host::VirtualMemory::selector2_begin,"separate arena");
    check(m.load_be32(0x1004,size)&&size==0x20000,"rounding");
    check(m.load_be32(base+0x10000,word)&&!word&&m.store_be32(base,42),"committed zeroed backing");
    check(!m.reservation(host::VirtualMemory::arena_begin),"no normal arena mutation");
    s.gpr[3]=0x1000;s.gpr[7]=3;before=s;
    check(k.call("xboxkrnl.exe",204,s,m)==ImportCallResult::unsupported&&s==before,"other selector not generalized");
    std::cout<<"Explicit hardware and opt-in selector2 profile isolation passed\n";
}
