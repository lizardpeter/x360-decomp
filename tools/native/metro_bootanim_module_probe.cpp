// Verify that the compiled entryless boot animation registers callable native
// functions. This deliberately never invokes any unverified export ABI.
#include <rex/kernel/function_dispatcher.h>
#include <rex/ppc/image.h>
#include <rex/ppc/recompiled_code.h>
#include <cstdint>
#include <iostream>
#include <map>
#include <set>

extern "C" void ReXRegisterModule(rex::kernel::IFunctionRegistrar*);
extern "C" const rex::ppc::PPCImage* ReXGetModuleImage();

namespace {
class Registrar final : public rex::kernel::IFunctionRegistrar {
 public:
  explicit Registrar(const rex::ppc::PPCImage& image):image_(image) {}
  bool SetFunction(rex::u32 address, PPCFunc* func) override {
    if (!address || (address&3) || !func ||
        address<image_.code_base ||
        std::uint64_t(address)>=std::uint64_t(image_.code_base)+image_.code_size) {
      valid=false;
      return false;
    }
    if (!entries.emplace(address,func).second) {
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
  std::cerr<<"BOOTANIM_NATIVE fail "<<stage<<"\n";
  return 1;
}
}
int main() {
  const auto* image=ReXGetModuleImage();
  if (!image || image->image_base!=0x98000000u || image->image_size!=638976u ||
      image->code_base!=0x9800E000u || !image->code_size || !image->func_mappings)
    return fail("image_layout");
  Registrar registrar(*image);
  ReXRegisterModule(&registrar);
  if (!registrar.valid || registrar.entries.size()<661) return fail("registration");
  std::set<rex::u32> seen;
  for (auto* m=image->func_mappings;m->address || m->host;++m) {
    const auto address=static_cast<rex::u32>(m->address);
    const auto it=registrar.entries.find(address);
    if (it==registrar.entries.end() || it->second!=m->host || !seen.insert(address).second)
      return fail("mapping_consistency");
  }
  if (seen.size()!=registrar.entries.size())return fail("mapping_count");
  constexpr rex::u32 exports[]={0x98020E60,0x98020EC8,0x98020ED8};
  for (auto address:exports) {
    if (!registrar.entries.contains(address))return fail("missing_export");
    std::cout<<"BOOTANIM_NATIVE pass export "<<std::hex<<address<<std::dec<<"\n";
  }
  if (registrar.entries.contains(image->image_base))return fail("nonexecutable_entry");
  std::cout<<"BOOTANIM_NATIVE pass registered="<<registrar.entries.size()
           <<" exports=3 guest_executed=false\n";
  return 0;
}
