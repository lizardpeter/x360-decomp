#include "host/kernel_startup.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace x360;
using abi::ImportCallResult;
static void require(bool good,const char* why){if(!good)throw std::runtime_error(why);}
int main(int argc,char** argv){
    if(argc!=4){std::cerr<<"usage: kernel_file_probe ROOT GUEST_PATH OUTPUT\n";return 2;}
    try{
        machine::AddressSpace memory;host::KernelStartup kernel;
        std::array<std::uint8_t,24> header{0x58,0x45,0x58,0x32};header[11]=24;
        require(kernel.install(memory,header,0x80001000,0x80002000),"startup install");
        kernel.enable_kernel_services(memory);
        require(kernel.files()->mount("flash:",argv[1]),"trusted resource tree mount");
        constexpr abi::Address base=0x100000,handle=base,iosb=base+8,attrs=base+16,desc=base+32,
            path=base+64,buffer=base+4096;
        constexpr std::uint32_t chunk=1024*1024;
        std::vector<std::uint8_t> storage(chunk+4096);
        require(memory.map(base,storage,true),"guest buffer map");
        auto put=[&](abi::Address at,std::uint32_t n){require(memory.store_be32(at,n),"guest store");};
        auto get=[&](abi::Address at){std::uint32_t n{};require(memory.load_be32(at,n),"guest load");return n;};
        auto invoke=[&](std::uint16_t o,std::initializer_list<std::uint32_t> args){
            abi::GuestCall s{};unsigned i=3;for(auto n:args)s.gpr[i++]=n;
            require(kernel.call("xboxkrnl.exe",o,s,memory)==ImportCallResult::completed,"unresolved kernel service");
            return static_cast<std::uint32_t>(s.gpr[3]);
        };
        std::string_view guest=argv[2];require(!guest.empty()&&guest.size()<=1024,"guest path length");
        put(attrs,0);put(attrs+4,desc);put(attrs+8,0x40);
        put(desc,(static_cast<std::uint32_t>(guest.size())<<16)|static_cast<std::uint32_t>(guest.size()+1));
        put(desc+4,path);
        require(memory.write(path,{reinterpret_cast<const std::uint8_t*>(guest.data()),guest.size()}),"guest path");
        require(invoke(0xdf,{handle,0x80000000,attrs,iosb,0x60})==0,"NtOpenFile");
        auto h=get(handle);
        require(invoke(0xe8,{h,iosb,buffer,56,34})==0,"NtQueryInformationFile");
        const auto expected=(std::uint64_t(get(buffer+40))<<32)|get(buffer+44);
        std::ofstream out(argv[3],std::ios::binary);require(bool(out),"output open");
        std::uint64_t total=0;
        std::vector<std::uint8_t> data(chunk);
        for(;;){
            const auto status=invoke(0xf0,{h,0,0,0,iosb,buffer,chunk,0});
            if(status==0xc0000011)break;
            require(status==0,"NtReadFile");
            auto n=get(iosb+4);require(n&&n<=chunk,"read count");
            require(memory.read(buffer,std::span(data).first(n)),"read output");
            out.write(reinterpret_cast<const char*>(data.data()),n);require(bool(out),"output write");
            total+=n;require(total<=expected,"read exceeds metadata");
        }
        require(total==expected,"resource size mismatch");
        require(invoke(0xcf,{h})==0,"NtClose");
        out.close();require(bool(out),"output close");
        std::cout<<total<<"\n";return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
