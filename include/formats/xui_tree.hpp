#pragma once
#include "formats/xui_values.hpp"
#include "formats/xui_timeline.hpp"
#include <istream>
#include <map>
#include <memory>
#include <variant>

namespace x360::formats::xui {
enum class PropertyType { boolean, integer, unsigned_integer, real, string, color, vector, quaternion, object, custom };
struct PropertyDefinition {
    std::string name;
    PropertyType type{};
    bool indexed{};
};
struct ClassDefinition {
    std::string name, base;
    std::vector<PropertyDefinition> properties;
};
// External, version-specific schema supplied explicitly by the caller.
// Definitions use source order, not numeric property IDs.
class ClassSchema {
public:
    static ClassSchema read(std::istream&);
    const ClassDefinition& find(std::string_view) const;
    std::vector<const ClassDefinition*> hierarchy(std::string_view) const;
private:
    std::map<std::string,ClassDefinition,std::less<>> classes_;
};
struct ColorWord { std::uint32_t packed{}; };
struct ShapeRef { std::size_t index{}; };
struct CompoundRef { std::size_t index{}; };
using PropertyValue=std::variant<bool,std::int32_t,std::uint32_t,float,std::string,ColorWord,Vec3,Quaternion,ShapeRef,CompoundRef>;
struct Property {
    std::string owner,name;
    PropertyType type{};
    bool indexed{};
    std::vector<PropertyValue> values;
};
using PropertyList=std::vector<Property>;
struct CompoundProperty {
    std::string class_name;
    std::uint32_t declared_count{};
    PropertyList properties;
};
struct KeyframeRecord {
    std::uint32_t frame{},token_base{};
    std::uint8_t flags{};
    std::vector<std::uint32_t> extra;
};
struct Channel {
    std::vector<std::string> path;
    std::string owner;
    PropertyType type{};
    std::optional<std::uint32_t> array_index;
};
struct Keyframe {
    KeyframeRecord metadata;
    std::vector<PropertyValue> values; // one value per channel
};
struct ElementTimeline {
    std::string target;
    std::size_t target_node{};
    std::vector<Channel> channels;
    std::vector<Keyframe> frames;
};
struct Element {
    std::size_t index{};
    std::string class_name;
    std::uint8_t flags{};
    std::shared_ptr<const PropertyList> properties;
    std::vector<Element> children;
    std::vector<std::size_t> markers;
    std::vector<ElementTimeline> timelines;
    const Property* property(std::string_view name) const noexcept;
};
struct TreeStatistics {
    std::size_t nodes{},inline_lists{},inline_properties{},shared_lists{},compound_lists{},
        timelines{},channels{},keyframes{},objects_with_children{},ambiguous_targets{};
};
struct SceneTree {
    SceneValues pools;
    std::vector<TimelineMarker> markers;
    std::vector<CompoundProperty> compounds;
    std::vector<KeyframeRecord> key_records;
    Element root;
    TreeStatistics statistics;
    static SceneTree parse(const Scene&,const ClassSchema&);
};
}
