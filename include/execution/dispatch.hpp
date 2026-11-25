#pragma once
#include "abi/guest_memory.hpp"
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace x360::execution {
enum class DispatchResult { executed, unresolved, memory_required, access_fault };
class Dispatch {
public:
    // Both entry types share one namespace. No partial registration on conflicts.
    bool register_module(std::string_view module, std::span<const abi::FunctionBinding> bindings);
    bool register_memory_module(std::string_view module, std::span<const abi::MemoryBinding> bindings);
    DispatchResult invoke(std::string_view module, abi::Address address, abi::GuestCall& state,
                          const abi::GuestMemory* memory=nullptr) const;
    std::size_t size() const noexcept { return bindings_.size(); }
private:
    using Key=std::pair<std::string,abi::Address>;
    using Entry=std::variant<abi::Function,abi::MemoryFunction>;
    std::map<Key,Entry> bindings_;
    template<class Binding> bool register_entries(std::string_view module,std::span<const Binding> bindings);
};
}
