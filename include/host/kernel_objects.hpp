#pragma once
#include "abi/import_provider.hpp"
#include "machine/address_space.hpp"
#include <map>
#include <memory>
namespace x360::host {
// Title-local handles to real guest-memory dispatcher bodies. No native OS
// handles or fabricated completion of blocking operations.
class KernelObjects {
public:
    explicit KernelObjects(machine::AddressSpace& memory):memory_(memory){}
    KernelObjects(const KernelObjects&)=delete;
    KernelObjects& operator=(const KernelObjects&)=delete;
    ~KernelObjects();
    static bool handles(std::uint16_t ordinal) noexcept;
    abi::ImportCallResult call(std::uint16_t ordinal,abi::GuestCall& state,abi::GuestMemory& memory);
private:
    enum class Kind {event,semaphore};
    struct Object {abi::Address address;Kind kind;};
    using Pointer=std::shared_ptr<Object>;
    machine::AddressSpace& memory_;
    std::map<std::uint32_t,Pointer> handles_;
    std::uint32_t next_handle_=0x100;
    Pointer lookup(std::uint32_t handle) const;
    bool close(std::uint32_t handle);
    std::uint32_t insert(Pointer object);
    static constexpr abi::Address arena_begin=0x51000000,arena_end=0x52000000;
};
}
