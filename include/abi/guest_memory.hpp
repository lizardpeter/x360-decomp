#pragma once
#include "abi/guest_call.hpp"
#include <cstdint>
#include <span>
namespace x360::abi {
// A guest address is not a host pointer. The backing machine supplies access.
class GuestMemory {
public:
    virtual ~GuestMemory()=default;
    virtual bool read(Address address,std::span<std::uint8_t> bytes) const noexcept=0;
    virtual bool write(Address address,std::span<const std::uint8_t> bytes) noexcept=0;
    bool load_be32(Address address,std::uint32_t& result) const noexcept {
        std::array<std::uint8_t,4> b{};
        if(!read(address,b))return false;
        result=(std::uint32_t(b[0])<<24)|(std::uint32_t(b[1])<<16)|(std::uint32_t(b[2])<<8)|b[3];
        return true;
    }
    bool store_be32(Address address,std::uint32_t value) noexcept {
        const std::array<std::uint8_t,4> b{std::uint8_t(value>>24),std::uint8_t(value>>16),std::uint8_t(value>>8),std::uint8_t(value)};
        return write(address,b);
    }
};
enum class MemoryCallResult { executed, access_fault };
using MemoryFunction=MemoryCallResult (*)(GuestCall&,const GuestMemory&) noexcept;
struct MemoryBinding { Address address; MemoryFunction implementation; };
}
