#include "execution/bootstrap_ppc.hpp"
#include "launcher/module_loader.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360;
using namespace x360::execution;
static void require(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
static void put(std::vector<std::uint8_t>& bytes,unsigned off,std::uint32_t w){
    for(unsigned i=0;i<4;++i)bytes[off+i]=static_cast<std::uint8_t>(w>>(24-8*i));
}
int main(){
    machine::AddressSpace memory;ModuleRegistry registry;
    ModuleManifest m{"test","synthetic",0x1000,0x1010,64,{{0x1010,32,0x60000020},{0x1030,16,0xc0000040}},
        {{0x1000,"provider",7,ImportKind::value},{0x102c,"provider",8,ImportKind::thunk}},{}};
    std::vector<std::uint8_t> code(64);
    put(code,0,7);put(code,16,0x38600005); // li r3,5
    put(code,20,0x90610000); // stw r3,0(r1)
    put(code,24,0x80810000); // lwz r4,0(r1)
    put(code,28,0x2c040005); // cmpwi r4,5
    put(code,32,0x4082000c); // bne 0x102c (not taken)
    put(code,36,0x80a01000); // lwz r5,0x1000(0)
    put(code,40,0x4e800020);put(code,44,0x01000008);
    require(launcher::load_verified_module(memory,registry,m,code)==launcher::LoadResult::loaded,"synthetic load");
    std::array<std::uint8_t,16> stack{};require(memory.map(0x2000,stack,true),"stack map");
    abi::GuestCall s;s.pc=m.entry;s.gpr[1]=0x2000;s.lr=0x3000;
    auto r=bootstrap_ppc(*registry.module("test"),memory,s,0x3000,100);
    require(r.stop==BootstrapStop::import_value&&r.retired==5&&r.ordinal==7&&r.address==0x1000&&s.pc==0x1024,"value import stop");
    require(r.trace.size()==6&&s.gpr[3]==5&&s.gpr[4]==5&&s.gpr[5]==0&&s.cr==0x20000000u,"trace/state");
    s.pc=0x102c;r=bootstrap_ppc(m,memory,s,0x3000,1);
    require(r.stop==BootstrapStop::import_thunk&&r.ordinal==8&&r.retired==0&&r.trace.empty(),"thunk stop");
    s.pc=0x1028;r=bootstrap_ppc(m,memory,s,0x3000,2);
    require(r.stop==BootstrapStop::return_address&&r.retired==1,"return");
    s.pc=m.entry;r=bootstrap_ppc(m,memory,s,0x3000,1);
    require(r.stop==BootstrapStop::budget&&r.retired==1&&s.pc==0x1014,"budget");
    s.gpr[1]=0x3000;r=bootstrap_ppc(m,memory,s,0x4000,1);
    require(r.stop==BootstrapStop::access_fault&&r.retired==0&&s.pc==0x1014,"fault");
    s.pc=0x1030;r=bootstrap_ppc(m,memory,s,0x4000,1);
    require(r.stop==BootstrapStop::non_executable&&r.retired==0,"noncode");
    // Unsupported words never advance or mutate the call state.
    ModuleManifest other{"other","synthetic",0x4000,0x4000,4,{{0x4000,4,0x60000020}},{},{}};
    std::array<std::uint8_t,4> bad{};require(launcher::load_verified_module(memory,registry,other,bad)==launcher::LoadResult::loaded,"bad code map");
    s.pc=0x4000;auto before=s;r=bootstrap_ppc(other,memory,s,0x5000,2);
    require(r.stop==BootstrapStop::unsupported_instruction&&s==before,"unsupported");
    std::cout<<"PowerPC bootstrap boundaries, stack, conditional branch, imports and faults passed\n";
}
