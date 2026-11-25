#pragma once
#include "abi/import_provider.hpp"
#include "machine/address_space.hpp"
#include "host/virtual_memory.hpp"
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
    void enable_virtual_memory(machine::AddressSpace& memory){virtual_memory_.emplace(memory);}
    enum class ProcessType:std::uint32_t {idle=0,user=1,system=2};
    void enable_heap_startup(ProcessType type){process_type_=type;}
    const std::map<abi::Address,Notification>& notifications() const noexcept{return notifications_;}
private:
    std::optional<VirtualMemory> virtual_memory_;
    std::optional<ProcessType> process_type_;
    bool ready_{};
    std::uint32_t header_bytes_{},header_count_{};
    abi::Address callback_begin_{},callback_end_{};
    std::map<abi::Address,Notification> notifications_;
};
}
