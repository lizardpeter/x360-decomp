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
    k.enable_kernel_services(m);auto* files=k.files();check(files,"file service");
    std::array<std::uint8_t,5> original{1,2,3,4,5};
    check(files->add_file("flash:/Dash.XEX",original),"add file");
    check(files->add_file("flash:/system/Xam.xex",original),"add child");
    check(!files->add_file("FLASH:/dash.xex",original),"case collision");
    check(!files->add_file("flash:/../secret",original),"unsafe path");
    check(!files->add_file("flash:/dash.xex/child",original),"parent file");
    std::array<std::uint8_t,1024> memory{};check(m.map(0x1000,memory,true),"args");
    auto put=[&](std::uint32_t p,std::uint32_t n){check(m.store_be32(p,n),"store");};
    auto get=[&](std::uint32_t p){std::uint32_t n{};check(m.load_be32(p,n),"load");return n;};
    auto call=[&](std::uint16_t o,std::initializer_list<std::uint32_t> args){
        abi::GuestCall s{};unsigned i=3;for(auto n:args)s.gpr[i++]=n;
        auto r=k.call("xboxkrnl.exe",o,s,m);return std::pair{r,static_cast<std::uint32_t>(s.gpr[3])};
    };
    auto status=[&](std::uint16_t o,std::initializer_list<std::uint32_t> args,std::uint32_t n=0){
        check(call(o,args)==std::pair{ImportCallResult::completed,n},"status");
    };
    auto string=[&](std::uint32_t desc,std::uint32_t buffer,std::string_view name){
        put(desc,(std::uint32_t(name.size())<<16)|std::uint32_t(name.size()+1));
        put(desc+4,buffer);check(m.write(buffer,{reinterpret_cast<const std::uint8_t*>(name.data()),name.size()}),"path bytes");
    };
    auto path=[&](std::string_view name,std::uint32_t root=0){
        put(0x1020,root);put(0x1024,0x1030);put(0x1028,0x40);string(0x1030,0x1100,name);
    };
    path("\\Device\\Flash\\DASH.XEX");
    status(0xdf,{0x1000,0x80000000,0x1020,0x1010,0x60});
    auto h=get(0x1000);check(host::KernelFiles::is_handle(h)&&get(0x1014)==1,"open actual bytes");
    status(0xf0,{h,0,0,0,0x1010,0x1200,3,0});check(get(0x1014)==3,"read length");
    std::array<std::uint8_t,3> data{};check(m.read(0x1200,data)&&data==std::array<std::uint8_t,3>{1,2,3},"first read");
    status(0xda,{h,0x1004,0});auto alias=get(0x1004);
    status(0xf0,{alias,0,0,0,0x1010,0x1200,4,0});check(get(0x1014)==2,"alias shared position");
    status(0xf0,{h,0,0,0,0x1010,0x1200,1,0},0xc0000011);
    put(0x1210,0);put(0x1214,1);status(0xf7,{h,0x1010,0x1210,8,14});
    status(0xe8,{alias,0x1010,0x1220,8,14});check(get(0x1224)==1,"seek shared");
    auto before=get(0x1224);check(call(0xf0,{alias,0,0,0,0x1010,0x5000,1,0}).first==ImportCallResult::fault,"bad buffer");
    status(0xe8,{h,0x1010,0x1220,8,14});check(get(0x1224)==before,"fault preserves position");
    status(0xff,{h},0xc0000022);status(0xe7,{0x1020,0x1220});check(get(0x1220+44)==5,"actual length metadata");
    status(0xcf,{h});status(0xcf,{h},0xc0000008);status(0xcf,{alias});
    path("flash:/");status(0xdf,{0x1000,1,0x1020,0x1010,1});auto dir=get(0x1000);
    string(0x1050,0x1140,"*.xex");status(0xe4,{dir,0,0,0,0x1010,0x1200,128,0x1050,1});
    check(get(0x1200+60)==8,"directory name length");
    status(0xe4,{dir,0,0,0,0x1010,0x1200,128,0,0},0x80000006);
    path("system",dir);status(0xdf,{0x1004,1,0x1020,0x1010,1});auto system=get(0x1004);
    path("xam.xex",system);status(0xdf,{0x1008,1,0x1020,0x1010,0x40});status(0xcf,{get(0x1008)});
    path("../dash.xex",system);status(0xdf,{0x1008,1,0x1020,0x1010,0x40},0xc0000033);
    status(0xcf,{system});status(0xcf,{dir});
    path("flash:/dash.xex");status(0xdf,{0x1000,0x40000000,0x1020,0x1010,0x40},0xc0000022);
    std::cout<<"Immutable flash paths, read/seek, handles, metadata, enumeration and rejection paths passed\n";
}
