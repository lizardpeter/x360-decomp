#pragma once
#include "formats/lua51.hpp"
namespace x360::formats::lua51 {
// Logical instruction starts exclude closure capture words and SETLIST data.
// Graph models possible normal intraprocedural flow, not calls or exceptions.
struct InstructionFlow {
    std::uint32_t pc{};
    std::uint8_t opcode{};
    std::vector<std::uint32_t> successors;
};
struct FunctionFlow {
    std::vector<InstructionFlow> instructions;
    std::size_t capture_words{},extra_words{},reachable{};
};
FunctionFlow verify_flow(const Prototype& function);
struct FlowCensus {
    std::size_t prototypes{},instructions{},edges{},branch_nodes{},terminal_nodes{},reachable{},unreachable{},capture_words{},extra_words{};
};
FlowCensus verify_flow(const Chunk& chunk);
}
