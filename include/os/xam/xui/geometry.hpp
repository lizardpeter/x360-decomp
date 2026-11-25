#pragma once
#include "formats/xui_values.hpp"
#include <vector>
namespace x360::os::xam::xui {
using formats::xui::Vec2;
// Candidate closed cubic-path interpretation, independently derived from the
// original CUST records. Geometry output is a portable rendering input, not a
// claim of retail tessellator pixel parity.
std::vector<Vec2> flatten_closed_shape(const formats::xui::CustomShape& shape,float tolerance=0.25f,
                                       unsigned max_depth=12);
}
