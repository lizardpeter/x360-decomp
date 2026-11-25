#pragma once
#include "abi/guest_memory.hpp"
#include <map>
#include <vector>
namespace x360::machine {
// Explicitly mapped, non-overlapping contiguous regions. Cross-region access
// is not supported yet, and must fail without partial output or writes.
struct RegionMapping {abi::Address base;std::span<const std::uint8_t> bytes;bool writable;};
class AddressSpace final : public abi::GuestMemory {
public:
    bool map(abi::Address base,std::span<const std::uint8_t> bytes,bool writable);
    // Transactional mapping: all regions are validated before any are added.
    bool map_batch(std::span<const RegionMapping> regions);
    bool read(abi::Address address,std::span<std::uint8_t> bytes) const noexcept override;
    bool write(abi::Address address,std::span<const std::uint8_t> bytes) noexcept override;
private:
    struct Region { std::vector<std::uint8_t> bytes; bool writable; };
    std::map<abi::Address,Region> regions_;
};
}
