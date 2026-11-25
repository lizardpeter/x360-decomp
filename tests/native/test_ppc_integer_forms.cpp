#include "execution/bootstrap_ppc.hpp"
#include "launcher/module_loader.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360;
using namespace x360::execution;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
static std::uint32_t d(unsigned op,unsigned rt,unsigned ra,unsigned imm){return op<<26|rt<<21|ra<<16|(imm&65535);}
static std::uint32_t x(unsigned rt,unsigned ra,unsigned rb,unsigned xo){return 31u<<26|rt<<21|ra<<16|rb<<11|xo<<1;}
static std::uint32_t m(unsigned op,unsigned rs,unsigned ra,unsigned sh,unsigned mb,unsigned me,unsigned rc=0){return op<<26|rs<<21|ra<<16|sh<<11|mb<<6|me<<1|rc;}
static abi::GuestCall run(std::uint32_t instruction,abi::GuestCall state, bool valid=true){
    std::array<std::uint8_t,4> bytes{};for(unsigned i=0;i<4;++i)bytes[i]=std::uint8_t(instruction>>(24-i*8));
    machine::AddressSpace memory;ModuleRegistry registry;
    ModuleManifest manifest{"test","test",0x1000,0x1000,4,{{0x1000,4,0x60000020}},{},{}};
    check(launcher::load_verified_module(memory,registry,manifest,bytes)==launcher::LoadResult::loaded,"map instruction");
    std::array<std::uint8_t,16> data{0x81,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    check(memory.map(0x2000,data,true),"map data");
    state.pc=0x1000;auto before=state;
    auto r=bootstrap_ppc(manifest,memory,state,0xf000,1);
    if(valid)check(r.stop==BootstrapStop::budget&&r.retired==1,"instruction retired");
    else check(r.stop==BootstrapStop::unsupported_instruction&&r.retired==0&&state==before,"invalid form mutated state");
    return state;
}
int main(){
    abi::GuestCall s;s.gpr[4]=0xffffffffffffffffull;s.xer=0x80000000;
    auto r=run(d(12,3,4,1),s);check(r.gpr[3]==0&&r.xer==0xa0000000,"addic carry and SO");
    s.gpr[4]=2;s.xer=0;
    r=run(d(8,3,4,1),s);check(r.gpr[3]==~0ull&&!(r.xer&0x20000000),"subfic borrow");
    s.gpr[4]=2;s.gpr[5]=2;s.xer=0x20000000;
    r=run(x(3,4,5,136),s);check(r.gpr[3]==0&&(r.xer&0x20000000),"subfe carry");
    s.xer=0;r=run(x(3,4,5,136),s);check(r.gpr[3]==~0ull&&!(r.xer&0x20000000),"subfe no carry");
    s.gpr[4]=0x1234567880000001ull;s.gpr[3]=0xfeedfaceffffffffull;
    r=run(m(21,4,3,0,31,29),s);check(r.gpr[3]==0x8000000180000001ull,"64-bit wrapped mask");
    r=run(m(20,4,3,0,31,31),s);check(r.gpr[3]==s.gpr[3],"insert bit");
    s.gpr[3]=0xfeedfacefffffffeull;r=run(m(20,4,3,0,31,31),s);check(r.gpr[3]==0xfeedfaceffffffffull,"insert preserves high bits");
    s.gpr[4]=0x2000;r=run(d(58,3,4,2),s);check(r.gpr[3]==0xffffffff81234567ull,"lwa sign extend");
    r=run(d(58,3,4,1),s);check(r.gpr[3]==0x8123456789abcdefull&&r.gpr[4]==0x2000,"ldu");
    run(d(58,4,4,1),s,false);
    s.lr=0x3457;s.cr=0x20000000;
    r=run(0x4dc20020,s);check(r.pc==0x3454,"hinted beqlr taken");
    s.cr=0;r=run(0x4dc20020,s);check(r.pc==0x1004,"hinted beqlr not taken");
    s.cr=0x20000000;r=run(0x40e20008,s);check(r.pc==0x1004,"hinted bne not taken");
    s.cr=0;r=run(0x40e20008,s);check(r.pc==0x1008,"hinted bne taken");
    auto before=s;r=run(x(0,0,4,278),s);before.pc=0x1004;check(r==before,"cache hint is nonmutating");
    std::cout<<"PPC carry, wrap masks, insert, DS loads, hinted branches and cache-hint regressions passed\n";
}
