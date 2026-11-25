#pragma once
#include "abi/guest_call.hpp"
#include <span>
namespace x360::os::dashboard {
// Build-qualified native functions; no guessed semantic names.
std::span<const abi::FunctionBinding> leaf_bindings_17559() noexcept;
}
