#pragma once
#include "formats/xui.hpp"
namespace x360::formats::xui {
// Structural evidence from all 477 modern original scenes. Only the
// independently cross-checked fields have semantic accessors.
struct SceneStructure {
    std::array<std::uint32_t,12> header{};
    std::vector<std::uint32_t> key_tokens;
    std::uint32_t root_class_index{}; // one-based STRN index
    Bytes remaining_data;
    std::size_t key_token_count() const noexcept{return header[8];}
    std::size_t name_record_count() const noexcept{return header[10];}
    static std::optional<SceneStructure> parse(const Scene& scene);
};
}
