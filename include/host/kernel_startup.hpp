#pragma once
#include "abi/import_provider.hpp"
#include "machine/address_space.hpp"
#include <map>
namespace x360::host {
struct Notification {abi::Address routine;std::uint32_t priority;};
class KernelStartup final:public abi::ImportProvider {
public:
    // Synthetic hosted loader objects, not original kernel object layouts.
    static constexpr abi::Address handle_cell=0x71000000,loader_object=0x71001000,header_address=0x71002000;
    bool install(machine::AddressSpace& memory,std::span<const std::uint8_t> verified_header,
                 abi::Address callback_begin,abi::Address callback_end);
    std::optional<std::uint32_t> value(std::string_view library,std::uint16_t ordinal) const override;
    abi::ImportCallResult call(std::string_view library,std::uint16_t ordinal,abi::GuestCall& state,abi::GuestMemory& memory) override;
    const std::map<abi::Address,Notification>& notifications() const noexcept{return notifications_;}
private:
    bool ready_{};
    std::uint32_t header_bytes_{},header_count_{};
    abi::Address callback_begin_{},callback_end_{};
    std::map<abi::Address,Notification> notifications_;
};
}
