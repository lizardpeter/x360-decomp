#pragma once
#include "formats/xui.hpp"
#include <map>
namespace x360::formats::xui {
enum class ResolveState {exact,normalized,missing,unsupported_scheme,ambiguous,malformed};
struct ResolvedResource {
    ResolveState state=ResolveState::malformed;
    Bytes data;
};
// Borrow archive objects and payload storage. Neither URI normalization nor
// lookup ever accesses the operating system or a network.
class Mounts {
public:
    void mount(std::string scheme,const Archive& archive);
    ResolvedResource resolve(std::string_view uri) const;
private:
    std::map<std::string,const Archive*,std::less<>> mounts_;
};
}
