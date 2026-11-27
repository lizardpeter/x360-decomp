#include "host/virtual_memory.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360;
using abi::ImportCallResult;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
int main(){
    machine::AddressSpace m;
    std::array<std::uint8_t,16> words{};check(m.map(0x1000,words,true),"out params");
    check(m.reserve(0x20000,0x30000,65536),"reserve");
    std::uint32_t n=42;check(!m.load_be32(0x20000,n)&&n==42,"uncommitted read");
    check(!m.map(0x30000,words,true),"reserved map collision");
    check(!m.reserve(0x40000,0x20000,65536),"reservation overlap");
    check(!m.reserve(0xffff0000,0x20000,65536),"range wrap");
    check(!m.commit(0x20000,4096,true),"wrong page size");
    check(m.commit(0x20000,0x30000,true),"commit all");
    check(m.load_be32(0x20000,n)&&!n,"zeroed commit");
    check(m.store_be32(0x20000,1)&&m.store_be32(0x30000,2)&&m.store_be32(0x40000,3),"writes");
    check(m.decommit(0x30000,65536),"partial decommit");
    check(m.load_be32(0x20000,n)&&n==1,"left fragment");
    check(m.load_be32(0x40000,n)&&n==3,"right fragment");
    check(!m.load_be32(0x30000,n),"middle inaccessible");
    check(m.commit(0x30000,65536,false)&&m.load_be32(0x30000,n)&&!n&&!m.store_be32(0x30000,1),"zeroed readonly recommit");
    check(m.protect(0x30000,65536,true),"protect committed page");
    check(m.store_be32(0x2fffe,0xaabbccdd)&&m.load_be32(0x2fffe,n)&&n==0xaabbccdd,"cross adjacent commit boundary");
    check(m.protect(0x30000,65536,false),"restore readonly");
    check(!m.store_be32(0x2fffe,0xffffffff)&&m.load_be32(0x2fffe,n)&&n==0xaabbccdd,"cross readonly write is atomic");
    check(m.protect(0x20000,0x30000,false)&&!m.store_be32(0x20000,9)&&!m.store_be32(0x40000,9),"protect across regions");
    check(m.protect(0x20000,0x30000,true)&&m.load_be32(0x40000,n)&&n==3,"restore permission preserves data");
    check(m.decommit(0x30000,65536),"decommit for hole checks");
    check(!m.protect(0x20000,0x30000,false)&&m.store_be32(0x20000,1),"failed protect leaves prior permissions");
    std::array<std::uint8_t,4> unchanged{9,8,7,6};
    check(!m.read(0x2fffe,unchanged)&&unchanged==std::array<std::uint8_t,4>{9,8,7,6},"read across hole leaves output untouched");
    check(!m.store_be32(0x2fffe,0xffffffff),"write across hole rejected");
    check(m.commit(0x30000,65536,true)&&m.load_be32(0x2fffe,n)&&n==0xaabb0000,"failed write preserved left bytes");
    check(!m.release(0x30000)&&m.release(0x20000)&&!m.load_be32(0x40000,n),"release whole range");
    check(m.map(0x30000,words,true),"released free for regular mapping");
    auto first=m.reserve_first(0x20000,0x60000,0x20000,65536);
    check(first==0x40000,"first free aligned range");
    check(!m.reserve_first(0x20000,0x60000,0x20000,65536),"no remaining gap");
    check(m.release(*first),"release first-fit");
    host::VirtualMemory service(m);abi::GuestCall s;
    s.gpr[3]=0x1000;s.gpr[4]=0x1004;s.gpr[5]=0x60002000;s.gpr[6]=4;
    check(m.store_be32(0x1004,0x100001),"reserve size");
    check(service.allocate(s,m)==ImportCallResult::completed&&!s.gpr[3],"reserve syscall");
    std::uint32_t address{},size{};check(m.load_be32(0x1000,address)&&address==host::VirtualMemory::arena_begin,"returned base");
    check(m.load_be32(0x1004,size)&&size==0x110000,"rounded size");
    check(!m.load_be32(address,n),"reservation still inaccessible");
    s.gpr[3]=0x1000;s.gpr[5]=0x60001000;check(m.store_be32(0x1004,0x10000),"commit size");
    check(service.allocate(s,m)==ImportCallResult::completed&&!s.gpr[3],"commit syscall");
    check(m.load_be32(address,n)&&!n&&m.store_be32(address,0x11223344),"committed page");
    check(!m.load_be32(address+65536,n),"uncommitted rest");
    s.gpr[3]=0x1000;s.gpr[7]=2;auto snapshot=s;
    check(service.allocate(s,m)==ImportCallResult::unsupported&&s==snapshot,"unknown memory selector");
    s.gpr[7]=0;s.gpr[3]=0x1010;snapshot=s;
    check(service.allocate(s,m)==ImportCallResult::fault&&s==snapshot,"invalid out pointer");
    check(m.release(address),"release service region");
    s.gpr[3]=0x1000;s.gpr[5]=0x60003000;check(m.store_be32(0x1000,0)&&m.store_be32(0x1004,65536),"combined args");
    check(service.allocate(s,m)==ImportCallResult::completed&&!s.gpr[3]&&m.load_be32(address,n)&&!n,"reserve+commit");
    auto args=[&](std::uint32_t a,std::uint32_t bytes,std::uint32_t kind){
        s={};s.gpr[3]=0x1000;s.gpr[4]=0x1004;s.gpr[5]=kind;
        check(m.store_be32(0x1000,a)&&m.store_be32(0x1004,bytes),"service args");
    };
    check(m.store_be32(address,0x12345678),"service test content");
    args(address,65536,2);s.gpr[6]=0x1008;
    check(service.protect(s,m)==ImportCallResult::completed&&!s.gpr[3]&&
          m.load_be32(0x1008,n)&&n==4&&!m.store_be32(address,9),"protect syscall old RW");
    args(address,65536,4);s.gpr[6]=0x1008;
    check(service.protect(s,m)==ImportCallResult::completed&&!s.gpr[3]&&
          m.load_be32(0x1008,n)&&n==2&&m.load_be32(address,n)&&n==0x12345678,"protect syscall restore");
    args(address,65536,0x4000);
    check(service.free(s,m)==ImportCallResult::completed&&!s.gpr[3]&&!m.load_be32(address,n)&&
          bool(m.reservation(address)),"decommit syscall");
    args(address,0,0x8000);
    check(service.free(s,m)==ImportCallResult::completed&&!s.gpr[3]&&!m.reservation(address)&&
          m.load_be32(0x1004,n)&&n==65536,"release syscall");
    std::cout<<"Virtual reserve/commit/decommit/release, permissions, first-fit and hosted allocation contracts passed\n";
}
