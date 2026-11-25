#pragma once
#include "formats/xui.hpp"
#include <optional>
#include <variant>
namespace x360::formats::lua51 {
using xui::Bytes;
// Preserve the exact number representation, including signed zero and NaNs.
struct Number {std::uint64_t bits;};
using Constant=std::variant<std::monostate,bool,Number,std::string>;
struct Local {std::string name;std::uint32_t start_pc,end_pc;};
struct Prototype {
    std::optional<std::string> source;
    std::uint32_t line_defined{},last_line_defined{};
    std::uint8_t upvalues{},parameters{},vararg{},max_stack{};
    std::vector<std::uint32_t> code;
    std::vector<Constant> constants;
    std::vector<Prototype> children;
    std::vector<std::uint32_t> lines;
    std::vector<Local> locals;
    std::vector<std::string> upvalue_names;
};
struct Chunk {Prototype main;static Chunk parse(Bytes input);};
struct Census {
    std::size_t prototypes{},words{},constants{},strings{},max_depth{},upvalues{},lines{},locals{},upvalue_names{},setlist_extra{};
    std::array<std::size_t,38> opcodes{};
    std::array<std::size_t,4> constant_types{};
};
Census census(const Chunk& chunk);
}
