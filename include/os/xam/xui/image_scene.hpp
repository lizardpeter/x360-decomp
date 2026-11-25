#pragma once
#include "formats/xui.hpp"
#include "formats/png.hpp"
namespace x360::os::xam::xui {
struct ImageScene {
    std::string scene_id, image_id, texture_uri;
    std::uint32_t canvas_width{},canvas_height{};
    double width{},height{},x{},y{},scale_x{},scale_y{},pivot_x{},pivot_y{};
};
// Only the independently identified three-element DATA layouts are accepted.
// Other XUI element grammars are explicitly unsupported.
std::optional<ImageScene> parse_image_scene(const formats::xui::Scene& scene);
// Portable diagnostic rasterizer, nearest sampling, transparent background.
// Not a reconstruction of the retail Xenos sampling or blending pipeline.
formats::png::Image render_image_scene(const ImageScene& scene,const formats::png::Image& texture);
}
