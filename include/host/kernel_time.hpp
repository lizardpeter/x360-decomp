#pragma once
#include "abi/import_provider.hpp"
#include <chrono>
namespace x360::host {
// Explicit hosted clock. Time uses 100-ns intervals since 1601 UTC; this
// provider does not claim the physical Xbox oscillator frequency.
class KernelTime {
public:
    using Tick=std::uint64_t;
    static constexpr std::uint32_t frequency=10000000;
    KernelTime():start_(std::chrono::steady_clock::now()){}
    static bool handles(std::uint16_t ordinal) noexcept;
    abi::ImportCallResult call(std::uint16_t ordinal,abi::GuestCall& state,abi::GuestMemory& memory) const;
    // Override samples for deterministic tests; both clocks stay coherent.
    void set_sample(Tick system,Tick uptime) noexcept{sample_={{system,uptime}};}
    void use_host_clock() noexcept{sample_.reset();}
private:
    struct Sample{Tick system,uptime;};
    std::chrono::steady_clock::time_point start_;
    std::optional<Sample> sample_;
    Sample now() const noexcept;
};
}
