#pragma once
#include "abi/guest_memory.hpp"
#include <optional>
#include <string_view>
namespace x360::abi {
enum class ImportCallResult {completed,unsupported,fault};
class ImportProvider {
public:
    virtual ~ImportProvider()=default;
    virtual std::optional<std::uint32_t> value(std::string_view library,std::uint16_t ordinal) const=0;
    // On success the runner, not the provider, transfers control back to LR.
    virtual ImportCallResult call(std::string_view library,std::uint16_t ordinal,GuestCall& state,GuestMemory& memory)=0;
};
}
