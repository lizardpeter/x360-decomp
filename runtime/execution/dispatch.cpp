#include "execution/dispatch.hpp"
namespace x360::execution {
template<class Binding>
bool Dispatch::register_entries(std::string_view module,std::span<const Binding> bindings) {
    if(module.empty()||bindings.empty())return false;
    std::map<Key,Entry> pending;
    for(const auto& b:bindings){
        if(!b.implementation||!b.address||(b.address&3u))return false;
        Key key{std::string(module),b.address};
        if(bindings_.contains(key)||!pending.emplace(std::move(key),Entry{b.implementation}).second)
            return false;
    }
    bindings_.merge(pending);
    return true;
}
bool Dispatch::register_module(std::string_view module,std::span<const abi::FunctionBinding> bindings){
    return register_entries(module,bindings);
}
bool Dispatch::register_memory_module(std::string_view module,std::span<const abi::MemoryBinding> bindings){
    return register_entries(module,bindings);
}
DispatchResult Dispatch::invoke(std::string_view module,abi::Address address,abi::GuestCall& state,
                                const abi::GuestMemory* memory) const {
    const auto i=bindings_.find(Key{std::string(module),address});
    if(i==bindings_.end())return DispatchResult::unresolved;
    if(auto fn=std::get_if<abi::Function>(&i->second)){
        (*fn)(state);
        return DispatchResult::executed;
    }
    if(!memory)return DispatchResult::memory_required;
    const auto fn=std::get<abi::MemoryFunction>(i->second);
    return fn(state,*memory)==abi::MemoryCallResult::executed?DispatchResult::executed:DispatchResult::access_fault;
}
}
