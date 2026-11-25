#include "execution/dispatch.hpp"
#include "os/dashboard/leaf_17559.hpp"
#include <array>
#include <cstdlib>
#include <iostream>
#include <random>

using namespace x360;
static void require(bool condition, const char* description) {
    if(!condition){std::cerr<<description<<"\n";std::exit(1);}
}
// Independent narrow instruction reference, restricted to the exact audited
// leaf pattern. No claim to be a general PowerPC interpreter.
static abi::GuestCall reference(abi::GuestCall s) {
    constexpr std::array<std::uint32_t,3> words{0x38600001,0x7d084378,0x4e800020};
    for(auto w:words) {
        auto op=w>>26;
        if(op==14) {
            auto d=(w>>21)&31, a=(w>>16)&31;
            auto imm=static_cast<std::int16_t>(w&0xffff);
            s.gpr[d]=(a?s.gpr[a]:0)+static_cast<std::uint64_t>(static_cast<std::int64_t>(imm));
            s.pc+=4;
        } else if(op==31 && ((w>>1)&1023)==444 && !(w&1)) {
            auto source=(w>>21)&31, dest=(w>>16)&31, b=(w>>11)&31;
            s.gpr[dest]=s.gpr[source]|s.gpr[b];
            s.pc+=4;
        } else if(w==0x4e800020) {
            s.pc=static_cast<abi::Address>(s.lr)&0xfffffffcu;
        } else {
            require(false,"unsupported reference instruction");
        }
    }
    return s;
}
int main() {
    execution::Dispatch dispatch;
    const auto bindings=os::dashboard::leaf_bindings_17559();
    require(bindings.size()==47,"incorrect binding count");
    require(dispatch.register_module("dash_17559",bindings),"initial registration failed");
    require(!dispatch.register_module("dash_17559",bindings),"duplicate registration accepted");
    require(dispatch.size()==47,"duplicate registration mutated dispatch");
    require(dispatch.register_module("independent_module",bindings.first(1)),"module namespaces conflict");
    std::array<abi::FunctionBinding,2> invalid{{{0x1000,bindings[0].implementation},{0x1001,bindings[0].implementation}}};
    require(!dispatch.register_module("invalid",invalid),"unaligned binding accepted");
    require(dispatch.size()==48,"failed registration was not atomic");
    std::array<abi::FunctionBinding,2> dup{{{0x1000,bindings[0].implementation},{0x1000,bindings[0].implementation}}};
    require(!dispatch.register_module("invalid",dup),"duplicate within batch accepted");
    require(!dispatch.register_module("invalid",{}),"empty batch accepted");
    std::mt19937_64 rng(17559);
    unsigned cases=0;
    for(auto binding:bindings) {
        for(unsigned i=0;i<256;i++) {
            abi::GuestCall actual;
            for(auto& reg:actual.gpr)reg=rng();
            actual.lr=rng();actual.ctr=rng();
            actual.cr=static_cast<std::uint32_t>(rng());actual.xer=static_cast<std::uint32_t>(rng());actual.pc=binding.address;
            if(i==0)actual.lr=0;
            if(i==1)actual.lr=~std::uint64_t{0};
            auto expected=reference(actual);
            require(dispatch.invoke("dash_17559",binding.address,actual)==execution::DispatchResult::executed,"known entry unresolved");
            require(actual==expected,"native function diverged from instruction reference");
            auto snapshot=actual;
            require(dispatch.invoke("xam_17559",binding.address,actual)==execution::DispatchResult::unresolved,"unknown module accepted");
            require(actual==snapshot,"unresolved dispatch changed state");
            ++cases;
        }
    }
    std::cout<<cases<<" native leaf/reference cases passed across "<<bindings.size()<<" original addresses\n";
}
