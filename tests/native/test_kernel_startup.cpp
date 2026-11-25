#include "host/kernel_startup.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360;
using abi::ImportCallResult;
static void require(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
static void put(std::span<std::uint8_t> b,unsigned off,std::uint32_t v){for(unsigned i=0;i<4;++i)b[off+i]=std::uint8_t(v>>(24-8*i));}
int main(){
    machine::AddressSpace m;host::KernelStartup k;
    std::array<std::uint8_t,64> header{};put(header,0,0x58455832);put(header,8,header.size());put(header,20,3);
    put(header,24,0x10100);put(header,28,0x12345678);
    put(header,32,0x10201);put(header,36,0x92000000);
    put(header,40,0x18002);put(header,44,48);
    require(k.install(m,header,0x80001000,0x80002000),"install");
    require(!k.install(m,header,0x80001000,0x80002000),"double install");
    std::uint32_t word{};require(k.value("xboxkrnl.exe",403)==host::KernelStartup::handle_cell,"value mapping");
    require(m.load_be32(host::KernelStartup::handle_cell,word)&&word==host::KernelStartup::loader_object,"cell");
    require(m.load_be32(word+0x58,word)&&word==host::KernelStartup::header_address,"header pointer");
    require(!m.store_be32(word,0),"immutable header");
    abi::GuestCall s;s.gpr[3]=word;s.gpr[4]=0x10100;
    require(k.call("xboxkrnl.exe",299,s,m)==ImportCallResult::completed&&s.gpr[3]==0x12345678,"inline value");
    s.gpr[3]=word;s.gpr[4]=0x10201;require(k.call("xboxkrnl.exe",299,s,m)==ImportCallResult::completed&&s.gpr[3]==word+36,"inline pointer");
    s.gpr[3]=word;s.gpr[4]=0x18002;require(k.call("xboxkrnl.exe",299,s,m)==ImportCallResult::completed&&s.gpr[3]==word+48,"offset pointer");
    s.gpr[3]=word;s.gpr[4]=0x20401;require(k.call("xboxkrnl.exe",299,s,m)==ImportCallResult::completed&&!s.gpr[3],"missing optional field");
    std::array<std::uint8_t,16> reg{};put(reg,0,0x80001040);put(reg,4,0x6c000000);
    require(m.map(0x3000,reg,true),"record map");s.gpr[3]=0x3000;s.gpr[4]=1;auto before=s;
    require(k.call("xboxkrnl.exe",21,s,m)==ImportCallResult::completed&&s==before,"void registration");
    require(k.notifications().size()==1&&k.notifications().begin()->second.priority==0x6c000000,"registration state");
    require(k.call("xboxkrnl.exe",21,s,m)==ImportCallResult::completed&&k.notifications().size()==1,"duplicate registration");
    s.gpr[4]=0;require(k.call("xboxkrnl.exe",21,s,m)==ImportCallResult::completed&&k.notifications().empty(),"unregister");
    s.gpr[3]=0x3010;require(k.call("xboxkrnl.exe",21,s,m)==ImportCallResult::fault,"invalid record");
    before=s;require(k.call("xboxkrnl.exe",300,s,m)==ImportCallResult::unsupported&&s==before,"unknown ordinal");
    host::KernelStartup bad;machine::AddressSpace other;put(header,44,63);
    require(!bad.install(other,header,0x80001000,0x80002000)&&!other.load_be32(host::KernelStartup::handle_cell,word),"malformed header rollback");
    std::cout<<"Hosted header field, module object and notification registration contracts passed\n";
}
