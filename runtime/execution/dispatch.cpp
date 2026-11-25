#include "execution/dispatch.hpp"

namespace x360::execution {
bool Dispatch::register_module(std::string_view module, std::span<const abi::FunctionBinding> bindings) {
    if(module.empty() || bindings.empty()) return false;
    std::map<Key,abi::Function> pending;
    for(const auto& b:bindings) {
        if(!b.implementation || !b.address || (b.address & 3u)) return false;
        Key key{std::string(module),b.address};
        if(bindings_.contains(key) || !pending.emplace(std::move(key),b.implementation).second)
            return false;
    }
    bindings_.merge(pending);
    return true;
}
DispatchResult Dispatch::invoke(std::string_view module, abi::Address address, abi::GuestCall& state) const {
    const auto i=bindings_.find(Key{std::string(module),address});
    if(i==bindings_.end()) return DispatchResult::unresolved;
    i->second(state);
    return DispatchResult::executed;
}
}
