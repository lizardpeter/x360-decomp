#pragma once
#include "execution/module_registry.hpp"
#include "machine/address_space.hpp"
namespace x360::launcher {
enum class LoadResult {loaded,invalid_manifest,invalid_image,import_word_mismatch,mapping_conflict};
// This takes a separately digest-verified loaded XEX image, not an XEX file.
// No executable bytes are executed, no imports patched, no guest startup called.
LoadResult load_verified_module(machine::AddressSpace& memory,execution::ModuleRegistry& registry,
                               execution::ModuleManifest manifest,std::span<const std::uint8_t> image);
}
