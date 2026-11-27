// Standalone registration proof. Never executes a guest entry or account API.
#include <rex/kernel/function_dispatcher.h>
#include <rex/ppc/image.h>
#include <rex/ppc/recompiled_code.h>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <map>
#include <set>
#include "profile_module_identity.hpp"

extern "C" void ReXRegisterModule(rex::kernel::IFunctionRegistrar*);
extern "C" const rex::ppc::PPCImage* ReXGetModuleImage();

namespace {
class Registrar final : public rex::kernel::IFunctionRegistrar {
 public:
  explicit Registrar(const rex::ppc::PPCImage& image):image_(image) {}
  bool SetFunction(rex::u32 address,PPCFunc* func) override {
    if (!address || (address&3) || !func ||
        address<image_.code_base ||
        std::uint64_t(address)>=std::uint64_t(image_.code_base)+image_.code_size ||
        !entries.emplace(address,func).second) {
      valid=false;
      return false;
    }
    return true;
  }
  const rex::ppc::PPCImage& image_;
  std::map<rex::u32,PPCFunc*> entries;
  bool valid=true;
};
int fail(const char* stage) {
  std::cerr<<"METRO_PROFILE_NATIVE fail "<<kName<<" "<<stage<<"\n";
  return 1;
}
}
int main() {
  const auto* image=ReXGetModuleImage();
  if (!image || image->image_base!=kBase || image->image_size!=kSize ||
      !image->code_size || !image->func_mappings ||
      image->code_base<kBase ||
      std::uint64_t(image->code_base)+image->code_size>std::uint64_t(kBase)+kSize)
    return fail("image_layout");
  Registrar registrar(*image);
  ReXRegisterModule(&registrar);
  if (!registrar.valid || !registrar.entries.contains(kEntry))return fail("entry_registration");
  std::set<rex::u32> seen;
  for (auto* m=image->func_mappings;m->address || m->host;++m) {
    const auto address=static_cast<rex::u32>(m->address);
    const auto it=registrar.entries.find(address);
    if (it==registrar.entries.end() || it->second!=m->host || !seen.insert(address).second)
      return fail("mapping_consistency");
  }
  if (seen.size()!=registrar.entries.size())return fail("mapping_count");
  std::size_t missing=0;
  for (auto address:kXamThunks) {
    if (!registrar.entries.contains(address)) {
      std::cerr<<"METRO_PROFILE_NATIVE missing_thunk "<<kName<<" "<<std::hex<<address<<std::dec<<"\n";
      ++missing;
    }
  }
  if (missing)return fail("original_xam_thunk_registration");
  std::cout<<"METRO_PROFILE_NATIVE pass "<<kName<<" registered="<<registrar.entries.size()
           <<" xam_thunks="<<std::size(kXamThunks)<<" guest_executed=false\n";
  return 0;
}
