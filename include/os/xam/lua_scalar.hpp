#pragma once
#include "formats/lua51_flow.hpp"
#include <span>
namespace x360::os::xam::lua {
using Scalar=std::variant<std::monostate,bool,double,std::string>;
enum class ResultCode {returned,unsupported,type_error,budget_exhausted};
struct Result {
    ResultCode code;
    std::vector<Scalar> values;
    std::size_t steps{};
};
// Restricted original Lua 5.1 scalar execution. No globals, tables,
// closures, metamethods, calls, native I/O, or numeric-string coercion.
bool eligible(const formats::lua51::Prototype& prototype);
Result execute(const formats::lua51::Prototype& prototype,std::span<const Scalar> arguments,
               std::size_t budget=4096);
}
