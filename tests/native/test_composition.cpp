#include "launcher/metro_17559.hpp"
#include "os/dashboard/leaf_17559.hpp"
#include "os/dashboard/memory_leaf_17559.hpp"
#include <array>
#include <cstdlib>
#include <iostream>
using namespace x360;
using execution::DispatchResult;
static void require(bool b,const char* message){if(!b){std::cerr<<message<<'\n';std::exit(1);}}
int main(){
    const auto plain=os::dashboard::leaf_bindings_17559();
    const auto memory=os::dashboard::memory_leaf_bindings_17559();
    execution::Dispatch dispatch;
    require(dispatch.register_module("dash_17559",plain),"plain registration");
    require(dispatch.register_memory_module("dash_17559",memory),"memory registration");
    require(dispatch.size()==52,"combined count");
    const std::array<abi::MemoryBinding,2> bad{{{0x1000,memory.front().implementation},{plain.front().address,memory.front().implementation}}};
    require(!dispatch.register_memory_module("dash_17559",bad),"cross-kind collision");
    require(dispatch.size()==52,"failed batch partially inserted");
    abi::GuestCall s;s.gpr[3]=0x1234;s.pc=memory.front().address;s.lr=0x2345678b;
    auto snapshot=s;
    require(dispatch.invoke("dash_17559",memory.front().address,s)==DispatchResult::memory_required&&s==snapshot,"missing memory");
    require(dispatch.invoke("dash_17559",0x1000,s)==DispatchResult::unresolved&&s==snapshot,"partial entry");
    require(dispatch.invoke("xam_17559",memory.front().address,s)==DispatchResult::unresolved&&s==snapshot,"module isolation");
    require(dispatch.invoke("dash_17559",plain.front().address,s)==DispatchResult::executed&&s.gpr[3]==1&&s.pc==0x23456788,"plain dispatch");
    launcher::Metro17559 metro;
    require(metro.registered_functions()==52,"profile binding count");
    require(metro.call(memory.front().address,s)==DispatchResult::access_fault,"invalid read not propagated");
    const std::array<std::uint8_t,8> zero{};
    require(metro.memory().map(0x1000,zero,true)&&metro.memory().map(0x2000,zero,true),"memory map");
    require(metro.memory().store_be32(0x1000,0x2000),"pointer");
    for(auto b:memory){
        for(auto word:{0xc0000017u,0xc0000005u,0u,0xffffffffu}){
            require(metro.memory().store_be32(0x2000,word),"word");
            abi::GuestCall state;state.gpr[3]=0x1000;state.lr=0x10004;state.pc=b.address;
            auto direct=state;
            require(b.implementation(direct,metro.memory())==abi::MemoryCallResult::executed,"direct implementation");
            require(metro.call(b.address,state)==DispatchResult::executed&&state==direct,"composition changed behavior");
        }
    }
    std::cout<<"52-entry composition and unified dispatcher checks passed\n";
}
