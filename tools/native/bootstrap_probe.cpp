#include "launcher/module_loader.hpp"
#include "execution/bootstrap_ppc.hpp"
#include "host/kernel_startup.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
using namespace x360;
using namespace execution;
static void require(bool b,const char* why){if(!b)throw std::runtime_error(why);}
static ModuleManifest parse(const char* path){
    std::ifstream in(path);require(bool(in),"manifest open failed");ModuleManifest m;
    std::string line;bool header=false;
    while(std::getline(in,line)){
        std::istringstream row(line);char kind;require(bool(row>>kind),"bad manifest row");
        if(kind=='M'){require(!header&&bool(row>>m.name>>m.build>>m.base>>m.size>>m.entry),"bad manifest header");header=true;}
        else if(kind=='S'){ModuleSection s;require(header&&bool(row>>s.address>>s.size>>s.flags),"bad section row");m.sections.push_back(s);}
        else if(kind=='I'){ImportSlot i;unsigned type,ordinal;require(header&&bool(row>>i.address>>i.library>>ordinal>>type)&&type<=1&&ordinal<=65535,"bad import row");i.kind=static_cast<ImportKind>(type);i.ordinal=ordinal;m.imports.push_back(std::move(i));}
        else if(kind=='E'){ExportSlot e;unsigned ordinal;require(header&&bool(row>>ordinal>>e.address)&&ordinal<=65535,"bad export row");e.ordinal=ordinal;m.exports.push_back(e);}
        else throw std::runtime_error("unknown manifest row");
        std::string extra;require(!(row>>extra),"trailing manifest field");
    }
    require(header,"missing manifest header");return m;
}
static std::vector<std::uint8_t> read(const char* path){
    std::ifstream in(path,std::ios::binary);require(bool(in),"image open failed");
    return {std::istreambuf_iterator<char>(in),{}};
}
static void be(std::ostream& out,std::uint64_t value,unsigned n){
    for(unsigned i=n;i>0;--i)out.put(static_cast<char>(value>>(8*(i-1))));
}
static void dump(std::ostream& out,const abi::GuestMemory& memory,abi::Address a,std::size_t n){
    std::vector<std::uint8_t> bytes(n);require(memory.read(a,bytes),"snapshot read failed");
    out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());
}
int main(int argc,char** argv){
    if(argc!=4&&argc!=5){std::cerr<<"usage: bootstrap_probe MANIFEST IMAGE OUTPUT_DIRECTORY\n";return 2;}
    try{
        auto manifest=parse(argv[1]);auto image=read(argv[2]);
        machine::AddressSpace memory;ModuleRegistry registry;
        require(launcher::load_verified_module(memory,registry,manifest,image)==launcher::LoadResult::loaded,"module mapping failed");
        constexpr abi::Address stack_base=0x70000000,sp=0x70008000,sentinel=0x7000fffc;
        std::vector<std::uint8_t> stack(65536);
        require(memory.map(stack_base,stack,true),"stack mapping failed");
        abi::GuestCall s;s.gpr[1]=sp;s.lr=sentinel;s.pc=manifest.entry;
        if(manifest.name=="xam.xex"){s.gpr[3]=manifest.base;s.gpr[4]=1;}
        const auto& m=*registry.module(manifest.name);
        host::KernelStartup hosted;
        if(argc==5){
            auto header=read(argv[4]);abi::Address begin=0,end=0;
            for(auto& section:m.sections)if(section.executable()){begin=section.address;end=section.address+section.size;break;}
            require(hosted.install(memory,header,begin,end),"hosted header install failed");
        }
        auto r=bootstrap_ppc(m,memory,s,sentinel,10000,argc==5?&hosted:nullptr);
        const auto path=std::filesystem::path(argv[3]);
        std::ofstream trace(path/"trace",std::ios::binary),state(path/"state",std::ios::binary),stack_out(path/"stack",std::ios::binary),image_out(path/"image_after",std::ios::binary);
        require(trace&&state&&stack_out&&image_out,"snapshot output open failed");
        for(auto& t:r.trace){be(trace,t.address,4);be(trace,t.word,4);}
        for(auto v:s.gpr)be(state,v,8);be(state,s.lr,8);be(state,s.ctr,8);be(state,s.cr,4);be(state,s.xer,4);be(state,s.pc,4);
        dump(stack_out,memory,stack_base,stack.size());
        std::size_t pos=0;
        for(auto& section:m.sections){
            auto start=std::size_t(section.address-m.base);
            if(start>pos)dump(image_out,memory,static_cast<abi::Address>(m.base+pos),start-pos);
            dump(image_out,memory,section.address,section.size);pos=start+section.size;
        }
        if(pos<m.size)dump(image_out,memory,static_cast<abi::Address>(m.base+pos),m.size-pos);
        trace.close();state.close();stack_out.close();image_out.close();
        require(trace&&state&&stack_out&&image_out,"snapshot output failed");
        if(argc==5){
            require(r.stop==BootstrapStop::unsupported_instruction,"unexpected hosted startup boundary");
            std::cout<<"unsupported "<<r.retired<<" "<<r.trace.size()<<" "<<s.pc<<" "<<r.services.size()<<" "<<hosted.notifications().size();
            for(auto& service:r.services)std::cout<<" "<<service.ordinal;
            for(auto& [routine,record]:hosted.notifications())std::cout<<" "<<routine<<" "<<record.priority;
            std::cout<<"\n";return 0;
        }
        require(r.stop==BootstrapStop::import_value||r.stop==BootstrapStop::import_thunk,"unexpected startup boundary");
        std::cout<<(r.stop==BootstrapStop::import_value?"value":"thunk")<<" "<<r.retired<<" "<<r.trace.size()<<" "
                 <<r.address<<" "<<s.pc<<" "<<r.library<<" "<<r.ordinal<<"\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
