#pragma once
#include "formats/xui.hpp"
#include <array>
#include <vector>
namespace x360::formats::xui {
using Vec2=std::array<float,2>;
using Vec3=std::array<float,3>;
using Quaternion=std::array<float,4>;
struct CustomSegment {Vec2 control1,control2,end;};
struct CustomShape {
    float width{},height{};
    std::vector<CustomSegment> segments;
};
struct SceneValues {
    std::vector<float> floats;
    std::vector<Vec3> vectors;
    std::vector<Quaternion> quaternions;
    // Preserve packed original color words; renderer channel semantics separate.
    std::vector<std::uint32_t> colors;
    std::vector<CustomShape> custom;
    static SceneValues parse(const Scene& scene);
};
}
