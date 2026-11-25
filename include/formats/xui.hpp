#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace x360::formats::xui {
using Bytes=std::span<const std::uint8_t>;
class FormatError : public std::runtime_error { public: using std::runtime_error::runtime_error; };
// These are immutable, zero-copy views. The caller must retain the original
// backing bytes for the lifetime of each archive, scene and string view.
struct ArchiveEntry {
    std::string_view name;
    std::uint32_t offset;
    Bytes data;
};
class Archive {
public:
    static Archive parse(Bytes input);
    const std::vector<ArchiveEntry>& entries() const noexcept {return entries_;}
    // Exact virtual name lookup. Identical duplicate entries resolve to the
    // first; conflicting duplicate data is rejected. No filesystem extraction.
    std::optional<Bytes> find(std::string_view name) const;
private:
    std::vector<ArchiveEntry> entries_;
};
struct Section {
    std::array<char,4> tag;
    Bytes data;
    std::string_view name() const noexcept{return {tag.data(),tag.size()};}
};
class Scene {
public:
    static Scene parse(Bytes input);
    const std::vector<Section>& sections() const noexcept{return sections_;}
    const std::vector<std::string_view>& strings() const noexcept{return strings_;}
    Bytes directory_prefix() const noexcept{return prefix_;}
    std::optional<Bytes> section(std::string_view tag) const noexcept;
    std::uint32_t string_units() const noexcept{return units_;}
private:
    Bytes prefix_;
    std::vector<Section> sections_;
    std::vector<std::string_view> strings_;
    std::uint32_t units_{};
};
struct LocalizedString {
    std::string_view text;
    // Mode 1 has four trailing bytes per string; semantic interpretation of
    // the first two bytes is not established. Preserve all four.
    std::array<std::uint8_t,4> metadata{};
};
class StringTable {
public:
    static StringTable parse(Bytes input);
    std::uint8_t mode() const noexcept{return mode_;}
    const std::vector<LocalizedString>& entries() const noexcept{return entries_;}
private:
    std::uint8_t mode_{};
    std::vector<LocalizedString> entries_;
};
}
