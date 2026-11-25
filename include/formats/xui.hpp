#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace x360::formats::xui {
using Bytes=std::span<const std::uint8_t>;
class FormatError : public std::runtime_error { public: using std::runtime_error::runtime_error; };
// Resource payloads and sections are immutable borrowed views. Names and
// strings are owned UTF-8 to support older UTF-16BE variants. Retain the input
// bytes for the lifetime of borrowed payload and section views.
struct ArchiveEntry {
    std::string name;
    std::uint32_t offset;
    Bytes data;
};
class Archive {
public:
    static Archive parse(Bytes input);
    std::uint32_t version() const noexcept{return version_;}
    const std::vector<ArchiveEntry>& entries() const noexcept {return entries_;}
    // Exact virtual name lookup. Identical duplicate entries resolve to the
    // first; conflicting duplicate data is rejected. No filesystem extraction.
    std::optional<Bytes> find(std::string_view name) const;
private:
    std::uint32_t version_{};
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
    std::uint32_t version() const noexcept{return version_;}
    const std::vector<std::string>& strings() const noexcept{return strings_;}
    Bytes directory_prefix() const noexcept{return prefix_;}
    std::optional<Bytes> section(std::string_view tag) const noexcept;
    std::uint32_t string_units() const noexcept{return units_;}
private:
    Bytes prefix_;
    std::vector<Section> sections_;
    std::vector<std::string> strings_;
    std::uint32_t version_{};
    std::uint32_t units_{};
};
struct LocalizedString {
    std::string text;
    // Mode 0 stores a named string as a text/identifier pair.
    std::string identifier;
    // Mode 1 has four trailing bytes per string; semantic interpretation of
    // the first two bytes is not established. Preserve all four.
    std::array<std::uint8_t,4> metadata{};
};
class StringTable {
public:
    static StringTable parse(Bytes input);
    std::uint8_t version() const noexcept{return version_;}
    std::uint8_t mode() const noexcept{return mode_;}
    const std::vector<LocalizedString>& entries() const noexcept{return entries_;}
private:
    std::uint8_t version_{},mode_{};
    std::vector<LocalizedString> entries_;
};
}
