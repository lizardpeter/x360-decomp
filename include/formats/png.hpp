#pragma once
#include "formats/xui.hpp"
namespace x360::formats::png {
struct Image {
    std::uint32_t width{},height{};
    std::vector<std::uint8_t> rgba; // straight-alpha RGBA8, top-left origin
};
// Observed original PNG subset, no gamma transformation or external metadata.
Image decode(xui::Bytes data);
}
