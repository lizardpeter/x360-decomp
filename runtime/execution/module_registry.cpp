#include "execution/module_registry.hpp"
#include <algorithm>
#include <set>
namespace x360::execution {
namespace {
constexpr auto address_limit=std::uint64_t{1}<<32;
bool contains(std::uint64_t base,std::uint64_t size,std::uint64_t a,std::uint64_t n=1){
    return a>=base&&a-base<=size&&n<=size-(a-base);
}
bool intersects(std::uint64_t a,std::uint64_t n,std::uint64_t b,std::uint64_t m){
    return a<b+m&&b<a+n;
}
bool valid(const ModuleManifest& m){
    if(m.name.empty()||m.build.empty()||!m.size||std::uint64_t(m.base)+m.size>address_limit)return false;
    if(!m.entry||!ModuleRegistry::executable(m,m.entry))return false;
    std::uint64_t last=m.base;
    for(auto& s:m.sections){
        if(!s.size||s.address<last||!contains(m.base,m.size,s.address,s.size))return false;
        last=std::uint64_t(s.address)+s.size;
    }
    std::set<abi::Address> slots;
    for(auto& i:m.imports){
        if(i.library.empty()||!i.ordinal||(i.address&3u)||!contains(m.base,m.size,i.address,4)||!slots.insert(i.address).second)return false;
        if(i.kind!=ImportKind::value&&i.kind!=ImportKind::thunk)return false;
        if(i.kind==ImportKind::thunk&&!ModuleRegistry::executable(m,i.address))return false;
    }
    std::set<std::uint16_t> ordinals;
    for(auto& e:m.exports)
        if(!e.ordinal||!contains(m.base,m.size,e.address)||!ordinals.insert(e.ordinal).second)return false;
    return true;
}
}
bool ModuleRegistry::executable(const ModuleManifest& m,abi::Address address) noexcept{
    return !(address&3u)&&std::any_of(m.sections.begin(),m.sections.end(),[&](auto& s){
        return s.executable()&&contains(s.address,s.size,address,4);
    });
}
bool ModuleRegistry::register_module(ModuleManifest m){
    std::sort(m.sections.begin(),m.sections.end(),[](auto& a,auto& b){return a.address<b.address;});
    if(!valid(m)||modules_.contains(m.name))return false;
    for(auto& [name,other]:modules_)
        if(intersects(m.base,m.size,other.base,other.size))return false;
    std::sort(m.imports.begin(),m.imports.end(),[](auto& a,auto& b){return a.address<b.address;});
    std::sort(m.exports.begin(),m.exports.end(),[](auto& a,auto& b){return a.ordinal<b.ordinal;});
    auto name=m.name;
    return modules_.emplace(std::move(name),std::move(m)).second;
}
const ModuleManifest* ModuleRegistry::module(std::string_view name) const noexcept{
    auto i=modules_.find(name);return i==modules_.end()?nullptr:&i->second;
}
LinkResult ModuleRegistry::resolve(std::string_view requester,abi::Address slot) const noexcept{
    auto m=module(requester);
    if(!m)return {LinkState::requester_missing,0};
    auto i=std::lower_bound(m->imports.begin(),m->imports.end(),slot,[](auto& a,auto b){return a.address<b;});
    if(i==m->imports.end()||i->address!=slot)return {LinkState::import_missing,0};
    auto p=module(i->library);
    if(!p)return {LinkState::provider_missing,0};
    auto e=std::lower_bound(p->exports.begin(),p->exports.end(),i->ordinal,[](auto& a,auto b){return a.ordinal<b;});
    if(e==p->exports.end()||e->ordinal!=i->ordinal)return {LinkState::ordinal_missing,0};
    if(i->kind==ImportKind::thunk&&!executable(*p,e->address))return {LinkState::non_executable_target,e->address};
    return {LinkState::address_resolved,e->address};
}
}
