#include "host/dispatcher_objects.hpp"
#include "machine/address_space.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360;
using abi::ImportCallResult;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
int main(){
    machine::AddressSpace m;
    std::array<std::uint8_t,128> bytes{};
    check(m.map(0x1000,bytes,true)&&m.map(0x2000,bytes,false),"map");
    auto invoke=[&](std::uint16_t o,std::uint32_t a,std::uint32_t b=0,std::uint32_t c=0,
                    std::uint32_t d=0,std::uint32_t e=0){
        abi::GuestCall s{};s.gpr[3]=a;s.gpr[4]=b;s.gpr[5]=c;s.gpr[6]=d;s.gpr[7]=e;
        auto code=host::DispatcherObjects::call(o,s,m);
        return std::pair{code,s.gpr[3]};
    };
    auto value=[&](std::uint32_t a){std::uint32_t n{};check(m.load_be32(a,n),"read");return n;};
    constexpr std::uint32_t manual=0x1000,automatic=0x1020,sem=0x1040,timeout=0x1070;
    check(invoke(0x70,manual,0,0).first==ImportCallResult::completed,"manual init");
    check(value(manual+8)==manual+8&&value(manual+12)==manual+8,"empty list");
    check(invoke(0xb0,manual,0,0,0,timeout).second==0x102,"unsignaled poll");
    check(invoke(0xb0,manual).first==ImportCallResult::unsupported,"blocking wait unsupported");
    check(invoke(0x9d,manual).second==0&&invoke(0x9d,manual).second==1,"event previous state");
    check(invoke(0xb0,manual).second==0&&invoke(0xb0,manual).second==0&&value(manual+4)==1,"manual remains signaled");
    check(invoke(0x8f,manual).second==1&&value(manual+4)==0,"reset");
    check(invoke(0x70,automatic,1,1).first==ImportCallResult::completed,"auto init");
    check(invoke(0xb0,automatic).second==0&&value(automatic+4)==0,"auto consumes signal");
    check(invoke(0xb0,automatic,0,0,0,timeout).second==0x102,"auto poll");
    check(invoke(0x74,sem,1,3).first==ImportCallResult::completed&&value(sem+16)==3,"semaphore init");
    check(invoke(0x88,sem,0,2).second==1&&value(sem+4)==3,"semaphore release");
    check(invoke(0x88,sem,0,1).first==ImportCallResult::unsupported&&value(sem+4)==3,"limit preserved");
    for(int i=2;i>=0;--i)check(invoke(0xb0,sem).second==0&&value(sem+4)==unsigned(i),"semaphore consume");
    check(invoke(0xb0,sem,0,0,0,timeout).second==0x102,"empty semaphore");
    check(invoke(0x9d,manual).second==0&&invoke(0x7f,manual).second==1&&value(manual+4)==0,"pulse with no waiters clears signal");
    constexpr std::uint32_t list=0x1060;
    check(m.store_be32(list,automatic)&&m.store_be32(list+4,sem),"wait set");
    auto multi=[&](unsigned kind,unsigned count=2){
        abi::GuestCall s{};s.gpr[3]=count;s.gpr[4]=list;s.gpr[5]=kind;s.gpr[9]=timeout;
        auto code=host::DispatcherObjects::call(0xaf,s,m);return std::pair{code,s.gpr[3]};
    };
    check(invoke(0x9d,automatic).second==0,"signal auto");
    check(multi(0).second==0x102&&value(automatic+4)==1,"failed all consumes nothing");
    check(invoke(0x88,sem,0,2).second==0,"release for multi wait");
    check(multi(0).second==0&&value(automatic+4)==0&&value(sem+4)==1,"all consumes both");
    check(multi(1).second==1&&value(sem+4)==0,"any returns selected index");
    check(multi(1).second==0x102,"any poll timeout");
    check(invoke(0x9d,automatic).second==0&&m.store_be32(list+4,automatic),"duplicate wait set");
    check(multi(0).first==ImportCallResult::unsupported&&value(automatic+4)==1,"duplicate consumes nothing");
    check(m.store_be32(list+4,0x3000),"invalid second object");
    check(multi(1).first==ImportCallResult::fault&&value(automatic+4)==1,"invalid second consumes nothing");
    check(m.store_be32(manual+8,0x3333),"simulate waiter");
    check(invoke(0x9d,manual).first==ImportCallResult::unsupported&&value(manual+4)==0,"no fake waiter wake");
    check(invoke(0x70,0x2000,0,0).first==ImportCallResult::fault,"readonly init");
    check(invoke(0x70,0x3000,0,0).first==ImportCallResult::fault,"unmapped init");
    std::cout<<"Hosted dispatcher event, semaphore and nonblocking wait contracts passed\n";
}
