#include "launcher/module_loader.hpp"
#include <array>
#include <cstdlib>
#include <iostream>
using namespace x360;
using namespace execution;
using launcher::LoadResult;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
static ModuleManifest manifest(std::string name,abi::Address base){
    return {std::move(name),"test",base,base+0x10,64,{{base+0x10,16,0x60000020},{base+0x20,16,0xc0000040}},{},{}};
}
int main(){
    machine::AddressSpace memory;ModuleRegistry registry;
    auto a=manifest("dash.xex",0x1000),b=manifest("xam.xex",0x2000);
    a.imports={{0x1000,"xam.xex",1,ImportKind::value},{0x1010,"xam.xex",1,ImportKind::thunk},
               {0x1014,"xam.xex",2,ImportKind::thunk},{0x1004,"xam.xex",2,ImportKind::value},
               {0x1008,"xam.xex",3,ImportKind::value},{0x100c,"xboxkrnl.exe",1,ImportKind::value}};
    b.exports={{1,0x2010},{2,0x2020}};
    std::array<std::uint8_t,64> image{},other{};
    image[3]=1;image[7]=2;image[11]=3;image[15]=1;image[16]=1;image[19]=1;image[20]=1;image[23]=2;
    check(launcher::load_verified_module(memory,registry,a,image)==LoadResult::loaded,"load caller");
    check(registry.resolve("dash.xex",0x1010).state==LinkState::provider_missing,"missing provider");
    check(launcher::load_verified_module(memory,registry,b,other)==LoadResult::loaded,"load provider");
    auto r=registry.resolve("dash.xex",0x1010);check(r.state==LinkState::address_resolved&&r.target==0x2010,"function target");
    r=registry.resolve("dash.xex",0x1014);check(r.state==LinkState::non_executable_target&&r.target==0x2020,"data target thunk");
    r=registry.resolve("dash.xex",0x1004);check(r.state==LinkState::address_resolved&&r.target==0x2020,"data target value");
    check(registry.resolve("dash.xex",0x1008).state==LinkState::ordinal_missing,"missing ordinal");
    check(registry.resolve("dash.xex",0x1018).state==LinkState::import_missing,"unregistered slot");
    check(registry.resolve("unknown",0x1010).state==LinkState::requester_missing,"unknown caller");
    check(registry.resolve("dash.xex",0x100c).state==LinkState::provider_missing,"kernel missing");
    std::uint32_t word{};check(memory.load_be32(0x1010,word)&&word==0x01000001,"original thunk preserved");
    check(!memory.store_be32(0x1010,0)&&memory.store_be32(0x1020,0xaabbccdd),"permissions");
    check(!memory.store_be32(0x1030,0),"read-only gap");
    auto invalid=manifest("invalid",0x3000);invalid.imports={{0x3010,"xam.xex",1,ImportKind::thunk}};
    check(launcher::load_verified_module(memory,registry,invalid,other)==LoadResult::import_word_mismatch,"reject bad import word");
    check(!registry.module("invalid")&&!memory.load_be32(0x3010,word),"mismatch rollback");
    auto collide=manifest("collision",0x4000);
    check(memory.map(0x4020,std::span(other).first(4),true),"collision map");
    check(launcher::load_verified_module(memory,registry,collide,other)==LoadResult::mapping_conflict,"collision rejected");
    check(!registry.module("collision")&&!memory.load_be32(0x4000,word),"mapping transaction rollback");
    check(launcher::load_verified_module(memory,registry,a,image)==LoadResult::invalid_manifest,"duplicate module");
    auto overlap=manifest("overlap",0x1020);
    check(launcher::load_verified_module(memory,registry,overlap,other)==LoadResult::invalid_manifest,"module overlap");
    check(registry.size()==2,"registry count after rollback");
    std::cout<<"module identity, transactional loading, original import words and permissions passed\n";
}
