#pragma once
#include "abi/guest_memory.hpp"
#include <map>
#include <optional>
#include <vector>
namespace x360::machine {
// Explicitly mapped, non-overlapping regions. Adjacent regions form a
// contiguous access range; holes or incompatible permissions fail atomically.
struct RegionMapping {abi::Address base;std::span<const std::uint8_t> bytes;bool writable;};
struct Reservation {abi::Address base;std::uint32_t size,page_size;};
class AddressSpace final : public abi::GuestMemory {
public:
    bool map(abi::Address base,std::span<const std::uint8_t> bytes,bool writable);
    // Transactional mapping: all regions are validated before any are added.
    bool map_batch(std::span<const RegionMapping> regions);
    // Virtual ranges are reserved without backing storage. Only committed
    // subranges may be read or written. This is a hosted address-space model.
    bool reserve(abi::Address base,std::uint32_t size,std::uint32_t page_size);
    std::optional<abi::Address> reserve_first(abi::Address lower,std::uint64_t upper,
                                              std::uint32_t size,std::uint32_t page_size);
    std::optional<Reservation> reservation(abi::Address address) const noexcept;
    bool commit(abi::Address base,std::uint32_t size,bool writable);
    // Change access only on a fully committed range within one reservation.
    bool protect(abi::Address base,std::uint32_t size,bool writable);
    bool decommit(abi::Address base,std::uint32_t size);
    bool release(abi::Address base);
    bool writable_range(abi::Address address,std::size_t size) const noexcept;
    bool read(abi::Address address,std::span<std::uint8_t> bytes) const noexcept override;
    bool write(abi::Address address,std::span<const std::uint8_t> bytes) noexcept override;
private:
    struct Region { std::vector<std::uint8_t> bytes; bool writable; };
    bool accessible(abi::Address address,std::size_t size,bool write) const noexcept;
    std::map<abi::Address,Region> regions_;
    std::map<abi::Address,Reservation> reservations_;
};
}
