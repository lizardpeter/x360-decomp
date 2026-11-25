#include "host/critical_sections.hpp"
#include "machine/address_space.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360;
using abi::ImportCallResult;
using host::CriticalSections;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
int main(){
    machine::AddressSpace m;
    constexpr abi::Address address=0x2000,owner=0x5000,other=0x6000;
    std::array<std::uint8_t,28> zero{};
    check(m.map(address,zero,true)&&m.map(0x3000,zero,false),"map");
    abi::GuestCall s;
    auto set=[&](){s.gpr[3]=address;};
    auto fields=[&](std::uint32_t lock,std::uint32_t depth,std::uint32_t thread){
        std::uint32_t n{};
        check(m.load_be32(address+16,n)&&n==lock,"lock count");
        check(m.load_be32(address+20,n)&&n==depth,"recursion count");
        check(m.load_be32(address+24,n)&&n==thread,"owner");
    };
    set();s.gpr[4]=257;
    check(CriticalSections::initialize(s,m,true)==ImportCallResult::completed&&s.gpr[3]==0,"spin init");
    std::uint32_t header{};check(m.load_be32(address,header)&&header==0x01020000,"spin round up");fields(0xffffffffu,0,0);
    set();s.gpr[4]=0xffffffffu;
    check(CriticalSections::initialize(s,m,true)==ImportCallResult::completed&&m.load_be32(address,header)&&header==0x01ff0000,"spin cap");
    set();auto snapshot=s;
    check(CriticalSections::enter(s,m,owner,false)==ImportCallResult::completed&&s==snapshot,"enter");
    fields(0,1,owner);
    set();check(CriticalSections::enter(s,m,owner,true)==ImportCallResult::completed&&s.gpr[3]==1,"recursive try");fields(1,2,owner);
    set();check(CriticalSections::enter(s,m,other,true)==ImportCallResult::completed&&!s.gpr[3],"contended try");fields(1,2,owner);
    set();snapshot=s;check(CriticalSections::enter(s,m,other,false)==ImportCallResult::unsupported&&s==snapshot,"contended blocking unsupported");
    check(CriticalSections::leave(s,m,other)==ImportCallResult::unsupported&&s==snapshot,"nonowner leave");
    fields(1,2,owner);
    check(CriticalSections::leave(s,m,owner)==ImportCallResult::completed&&s==snapshot,"recursive leave");fields(0,1,owner);
    check(CriticalSections::leave(s,m,owner)==ImportCallResult::completed,"last leave");fields(0xffffffffu,0,0);
    check(CriticalSections::leave(s,m,owner)==ImportCallResult::unsupported,"unowned leave");
    check(CriticalSections::enter(s,m,other,false)==ImportCallResult::completed,"new owner");fields(0,1,other);
    check(m.store_be32(address+16,5),"simulate waiters");
    check(CriticalSections::leave(s,m,other)==ImportCallResult::unsupported,"waiters unresolved");fields(5,1,other);
    s.gpr[3]=0x3000;check(CriticalSections::initialize(s,m,false)==ImportCallResult::fault,"readonly init");
    s.gpr[3]=0x4000;check(CriticalSections::enter(s,m,owner,false)==ImportCallResult::fault,"unmapped");
    std::cout<<"Single-thread critical-section spin, recursion, contention, release and fault contracts passed\n";
}
