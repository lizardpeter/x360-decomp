#pragma once
#include "abi/guest_call.hpp"
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>
namespace x360::execution {
struct ModuleSection {
    abi::Address address{};
    std::uint32_t size{},flags{};
    bool executable() const noexcept{return (flags&0x20000000u)!=0;}
    bool writable() const noexcept{return (flags&0x80000000u)!=0;}
};
enum class ImportKind:std::uint8_t {value=0,thunk=1};
struct ImportSlot {
    abi::Address address{};
    std::string library;
    std::uint16_t ordinal{};
    ImportKind kind{};
};
struct ExportSlot {std::uint16_t ordinal{};abi::Address address{};};
struct ModuleManifest {
    std::string name,build;
    abi::Address base{},entry{};
    std::uint32_t size{};
    std::vector<ModuleSection> sections;
    std::vector<ImportSlot> imports;
    std::vector<ExportSlot> exports;
};
enum class LinkState {address_resolved,requester_missing,import_missing,provider_missing,ordinal_missing,non_executable_target};
struct LinkResult {
    LinkState state{};
    abi::Address target{};
};
class ModuleRegistry {
public:
    bool register_module(ModuleManifest module);
    const ModuleManifest* module(std::string_view name) const noexcept;
    LinkResult resolve(std::string_view requester,abi::Address slot) const noexcept;
    std::size_t size() const noexcept{return modules_.size();}
    void swap(ModuleRegistry& other) noexcept {modules_.swap(other.modules_);}
    static bool executable(const ModuleManifest& m,abi::Address address) noexcept;
private:
    std::map<std::string,ModuleManifest,std::less<>> modules_;
};
}
