#pragma once
#include "abi/guest_call.hpp"
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace x360::execution {
enum class DispatchResult { executed, unresolved };
class Dispatch {
public:
    // Registration is atomic: duplicate or invalid entries reject the entire batch.
    bool register_module(std::string_view module, std::span<const abi::FunctionBinding> bindings);
    DispatchResult invoke(std::string_view module, abi::Address address, abi::GuestCall& state) const;
    std::size_t size() const noexcept { return bindings_.size(); }
private:
    using Key = std::pair<std::string,abi::Address>;
    std::map<Key,abi::Function> bindings_;
};
}
