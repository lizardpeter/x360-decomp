#pragma once
#include "formats/lua51_flow.hpp"
#include <compare>
#include <memory>
#include <span>
namespace x360::os::xam::lua {
struct TableRef {std::uint32_t id;auto operator<=>(const TableRef&) const=default;};
struct ClosureRef {std::uint32_t id;auto operator<=>(const ClosureRef&) const=default;};
struct BuiltinRef {std::uint8_t id;auto operator<=>(const BuiltinRef&) const=default;};
using Value=std::variant<std::monostate,bool,double,std::string,TableRef,ClosureRef,BuiltinRef>;
enum class VmCode {returned,type_error,unsupported,budget_exhausted,malformed};
struct VmResult {VmCode code;std::vector<Value> values;std::size_t steps{};std::string detail;};
struct VmLimits {
    std::size_t steps=100000,max_depth=64,max_registers=4096,max_objects=8192,
        max_entries=65536,max_string=1024*1024;
};
// Authored, bounded Lua 5.1 VM core. The host controls all exposed builtins.
// No metatables, userdata, OS/file/network libraries, or garbage collection.
class Vm {
public:
    explicit Vm(VmLimits limits={});
    ~Vm();
    Vm(Vm&&) noexcept;
    Vm& operator=(Vm&&) noexcept;
    Vm(const Vm&)=delete;
    Vm& operator=(const Vm&)=delete;
    VmResult run(const formats::lua51::Prototype& p,std::span<const Value> args={});
    VmResult invoke(const Value& function,std::span<const Value> args={});
    Value global(std::string_view name) const;
    bool set_global(std::string_view name,Value value);
    std::optional<TableRef> new_table();
    std::optional<Value> raw_get(TableRef table,const Value& key) const;
    bool raw_set(TableRef table,Value key,Value value);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
