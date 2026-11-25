#include "host/kernel_startup.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360;
using abi::ImportCallResult;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
int main(){
    machine::AddressSpace memory;host::KernelStartup kernel;
    std::array<std::uint8_t,24> header{'X','E','X','2',0,0,0,0,0,0,0,24};
    check(kernel.install(memory,header,0x80001000,0x80002000),"install");
    abi::GuestCall state;state.gpr[3]=0x1234;auto before=state;
    check(kernel.call("xboxkrnl.exe",102,state,memory)==ImportCallResult::unsupported&&state==before,"not configured");
    kernel.enable_heap_startup(host::KernelStartup::ProcessType::system);
    check(kernel.call("xboxkrnl.exe",102,state,memory)==ImportCallResult::completed&&state.gpr[3]==2,"system process");
    kernel.enable_heap_startup(host::KernelStartup::ProcessType::user);
    check(kernel.call("xboxkrnl.exe",102,state,memory)==ImportCallResult::completed&&state.gpr[3]==1,"user process");
    std::array<std::uint8_t,28> initial{};initial.fill(0x55);
    check(memory.map(0x2000,initial,true)&&memory.map(0x3000,initial,false),"map");
    state.gpr[3]=0x2000;before=state;
    check(kernel.call("xboxkrnl.exe",302,state,memory)==ImportCallResult::completed&&state==before,"initialize");
    std::array<std::uint8_t,28> result{};
    check(memory.read(0x2000,result),"read");
    check(result==std::array<std::uint8_t,28>{1,0,0x55,0x55,0,0,0,0,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,255,255,255,255,0,0,0,0,0,0,0,0},"exact initialized fields and preserved opaque bytes");
    for(auto address:{0x2001u,0x2010u,0x3000u,0x4000u,0u}){
        state.gpr[3]=address;before=state;
        check(kernel.call("xboxkrnl.exe",302,state,memory)==ImportCallResult::fault&&state==before,"invalid record");
    }
    check(memory.read(0x3000,result)&&result==initial,"readonly preserved");
    std::cout<<"Hosted process-type and exact critical-section initialization checks passed\n";
}
