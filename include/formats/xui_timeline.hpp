#pragma once
#include "formats/xui.hpp"
#include <optional>
namespace x360::formats::xui {
struct TimelineMarker {
    std::uint16_t name_index; // original one-based STRN reference
    std::uint16_t frame;
    std::uint16_t kind; // preserve original type; playback semantics not inferred
    std::optional<std::uint16_t> related_name_index;
};
class TimelineNames {
public:
    static TimelineNames parse(const Scene& scene);
    const std::vector<TimelineMarker>& markers() const noexcept{return markers_;}
    // Several independent element timelines can reuse names. Preserve all
    // matches and their original order; do not silently select a first hit.
    std::vector<std::size_t> find(const Scene& scene,std::string_view name) const;
private:
    std::vector<TimelineMarker> markers_;
};
}
