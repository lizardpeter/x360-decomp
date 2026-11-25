#include "launcher/module_loader.hpp"
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
int main(int argc,char** argv){
    if(argc!=5){std::cerr<<"usage: x360_module_probe DASH_MANIFEST DASH_IMAGE XAM_MANIFEST XAM_IMAGE\n";return 2;}
    try{
        auto dash=parse(argv[1]),xam=parse(argv[3]);
        auto dash_image=read(argv[2]),xam_image=read(argv[4]);
        machine::AddressSpace memory;ModuleRegistry registry;
        require(launcher::load_verified_module(memory,registry,dash,dash_image)==launcher::LoadResult::loaded,"dashboard mapping failed");
        require(launcher::load_verified_module(memory,registry,xam,xam_image)==launcher::LoadResult::loaded,"XAM mapping failed");
        std::size_t resolved=0,nonexec=0,missing=0,slots=0,exec_exports=0,other_exports=0;
        std::set<unsigned> kernel_ordinals,xam_ordinals;
        for(auto m:{&dash,&xam}){
            auto entry=m->entry;std::uint32_t word{};
            require(memory.load_be32(entry,word)&&word==0x7d8802a6u,"original entry instruction mismatch");
            require(!memory.store_be32(entry,word),"entry is writable");
            for(auto& s:m->sections){
                if(s.size<4)continue;
                require(memory.load_be32(s.address,word),"section not mapped");
                require(memory.store_be32(s.address,word)==s.writable(),"section permission mismatch");
            }
            for(auto& i:m->imports){
                ++slots;require(memory.load_be32(i.address,word),"import slot unreadable");
                require((word>>24)==static_cast<unsigned>(i.kind)&&(word&0xffffu)==i.ordinal,"original import word changed");
                auto r=registry.resolve(m->name,i.address);
                if(i.library=="xboxkrnl.exe"){
                    require(r.state==LinkState::provider_missing,"kernel unexpectedly available");++missing;kernel_ordinals.insert(i.ordinal);
                }else{
                    require(i.library=="xam.xex","unknown provider");xam_ordinals.insert(i.ordinal);
                    if(r.state==LinkState::address_resolved)++resolved;
                    else if(r.state==LinkState::non_executable_target){
                        require(i.ordinal==987&&r.target==0x81a87f20u&&i.kind==ImportKind::thunk,"unexpected non-executable target");
                        ++nonexec;
                    }else throw std::runtime_error("unexpected unresolved XAM import");
                }
            }
        }
        for(auto& e:xam.exports){if(ModuleRegistry::executable(xam,e.address))++exec_exports;else ++other_exports;}
        require(registry.size()==2,"module count");
        std::cout<<"slots="<<slots<<" xam_ordinals="<<xam_ordinals.size()<<" resolved_slots="<<resolved
                 <<" nonexec_thunks="<<nonexec<<" kernel_missing_slots="<<missing<<" kernel_ordinals="<<kernel_ordinals.size()
                 <<" xam_exports="<<xam.exports.size()<<" exec_exports="<<exec_exports<<" data_exports="<<other_exports<<'\n';
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
