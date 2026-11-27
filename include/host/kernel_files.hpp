#pragma once
#include "abi/import_provider.hpp"
#include "machine/address_space.hpp"
#include <filesystem>
#include <map>
#include <memory>
#include <string>
namespace x360::host {
// Immutable title-local resource snapshot. Guest paths never escape into
// arbitrary host filesystem access; only explicitly mounted bytes are visible.
class KernelFiles {
public:
    explicit KernelFiles(machine::AddressSpace& memory):memory_(memory){}
    bool mount(std::string_view volume,const std::filesystem::path& trusted_root);
    bool add_file(std::string_view path,std::span<const std::uint8_t> bytes);
    bool add_directory(std::string_view path);
    static bool handles(std::uint16_t ordinal) noexcept;
    static bool is_handle(std::uint32_t h) noexcept{return h>=0x40000000u&&h<0x50000000u;}
    abi::ImportCallResult call(std::uint16_t ordinal,abi::GuestCall& state,abi::GuestMemory& memory);
private:
    struct Node {std::string display;bool directory;std::vector<std::uint8_t> bytes;};
    struct Open {std::string path;std::uint64_t position{};bool readable{};std::vector<std::string> scan;std::size_t cursor{};bool started{};};
    machine::AddressSpace& memory_;
    std::map<std::string,Node> nodes_;
    std::map<std::uint32_t,std::shared_ptr<Open>> open_;
    std::uint64_t total_bytes_{};
    std::uint32_t next_=0x40000000u;
    static constexpr std::uint64_t budget=512ull*1024*1024;
    std::uint32_t insert(std::shared_ptr<Open> object);
    std::pair<std::uint32_t,std::string> object_path(abi::Address attrs) const;
    bool add(std::string_view path,bool directory,std::span<const std::uint8_t> bytes);
};
}
