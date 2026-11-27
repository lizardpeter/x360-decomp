#pragma once
#include "abi/import_provider.hpp"
#include "machine/address_space.hpp"
#include "host/virtual_memory.hpp"
#include "host/kernel_objects.hpp"
#include "host/kernel_pool.hpp"
#include "host/kernel_files.hpp"
#include "host/kernel_time.hpp"
#include "host/kernel_tls.hpp"
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
    void enable_virtual_memory(machine::AddressSpace& memory,bool diagnostic_selector2=false){virtual_memory_.emplace(memory,diagnostic_selector2);}
    // Explicit opt-in keeps the established narrow original trace profiles unchanged.
    void enable_kernel_services(machine::AddressSpace& memory){
        if(!objects_)objects_.emplace(memory);
        if(!pool_)pool_.emplace(memory);
        if(!files_)files_.emplace(memory);
        if(!time_)time_.emplace();
        if(!tls_)tls_.emplace();
        if(diagnostic_thread_)tls_->add_thread(diagnostic_thread_);
    }
    KernelTime* time() noexcept{return time_?&*time_:nullptr;}
    KernelTls* tls() noexcept{return tls_?&*tls_:nullptr;}
    KernelFiles* files() noexcept{return files_?&*files_:nullptr;}
    static constexpr abi::Address hardware_info_address=0x71000100;
    bool install_hardware_info(machine::AddressSpace& memory,const std::array<std::uint8_t,16>& bytes);
    enum class ProcessType:std::uint32_t {idle=0,user=1,system=2};
    void enable_heap_startup(ProcessType type){process_type_=type;}
    // Opt-in diagnostic identity; no guest scheduler is installed.
    void set_diagnostic_thread(abi::Address owner){diagnostic_thread_=owner;if(tls_&&owner)tls_->add_thread(owner);}
    const std::map<abi::Address,Notification>& notifications() const noexcept{return notifications_;}
private:
    std::optional<VirtualMemory> virtual_memory_;
    std::optional<KernelObjects> objects_;
    std::optional<KernelPool> pool_;
    std::optional<KernelFiles> files_;
    std::optional<KernelTime> time_;
    std::optional<KernelTls> tls_;
    std::optional<ProcessType> process_type_;
    abi::Address diagnostic_thread_{};
    bool hardware_ready_{};
    bool ready_{};
    std::uint32_t header_bytes_{},header_count_{};
    abi::Address callback_begin_{},callback_end_{};
    std::map<abi::Address,Notification> notifications_;
};
}
