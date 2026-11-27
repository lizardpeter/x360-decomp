#!/usr/bin/env python3
"""Implement bounded native XConfig console preferences and checked guest export I/O.

Category 7 has documented user preference selectors. These are title-host
settings, not synthetic physical console configuration or security state.
"""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

def replace(source,old,new):
    if source.count(old)!=1 or new in source:
        raise ValueError("unexpected XConfig source anchor: "+old[:80])
    return source.replace(old,new,1)

PREFS = """
  // User-controlled console preferences exposed to original XAM. These
  // describe the hosted title, not a physical console's flash contents.
  REX_SETTING(u32, console_screensaver, 0x1000, "XConfig screensaver preference");
  REX_SETTING(u32, console_auto_shutdown, 0, "XConfig idle shutdown preference");
  REX_SETTING(u32, console_camera_flags, 1, "XConfig camera preferences");
  REX_SETTING(u32, console_keyboard_layout, 0, "XConfig keyboard layout preference");
  REX_SETTING(u32, console_captions, 0, "XConfig closed captions preference");
  REX_SETTING(u32, console_caption_flags, 0, "XConfig closed caption style flags");
"""

HELPER = r'''
namespace {
struct ConsolePreference {
  rex::Setting<u32>* setting{};
  u16 bytes{};
};

ConsolePreference LookupConsolePreference(u16 selector) {
  auto& config = kernel::GetCurrentState().GetKernelSettings();
  switch (selector) {
    case 0x01: return {&config.console_screensaver, 2};
    case 0x02: return {&config.console_auto_shutdown, 2};
    case 0x04: return {&config.console_camera_flags, 4};
    case 0x07: return {&config.console_keyboard_layout, 2};
    case 0x12: return {&config.console_captions, 1};
    case 0x13: return {&config.console_caption_flags, 4};
    default: return {};
  }
}

bool ValidPreference(u16 selector, u32 value) {
  switch (selector) {
    case 0x01: return value == 0x000A || value == 0x1000;
    case 0x02: return value == 0 || value == 0x003C || value == 0x0168;
    case 0x07: return value <= 0xFFFF;
    case 0x12: return value <= 1;
    case 0x04:
    case 0x13: return true; // opaque user preference flags, not hardware access
    default: return false;
  }
}
}  // namespace
'''

GET_CATEGORY = r'''    case 0x0007: {
      const auto pref = LookupConsolePreference(setting);
      if (!pref.setting) {
        REXKRNL_WARN("METRO_XCONFIG unsupported console setting=0x{:04X}", setting);
        return X_STATUS_INVALID_PARAMETER_2;
      }
      const u32 observed = pref.setting->Get();
      if (!ValidPreference(setting, observed)) {
        REXKRNL_WARN("METRO_XCONFIG invalid hosted preference setting=0x{:04X}", setting);
        return X_STATUS_INVALID_PARAMETER_2;
      }
      setting_size = pref.bytes;
      if (pref.bytes == 1) value[0] = static_cast<u8>(observed);
      else if (pref.bytes == 2) memory::store<be_u16>(value, static_cast<u16>(observed));
      else memory::store<be_u32>(value, observed);
      break;
    }
'''

OLD_EXPORT = """u32 ExGetXConfigSetting_entry(u16 category, u16 setting, MappedVoid buffer_ptr, u16 buffer_size,
                              MappedU16 required_size_ptr) {
  u16 required_size = 0;
  X_STATUS result = ExGetXConfigSetting(category, setting, buffer_ptr, buffer_size, &required_size);

  if (required_size_ptr) {
    *required_size_ptr = required_size;
  }

  return result;
}"""
NEW_EXPORT = r'''u32 ExGetXConfigSetting_entry(u16 category, u16 setting, u32 buffer, u16 buffer_size,
                              u32 required_size_ptr) {
  auto& guest = kernel::GetCurrent().GetGuestMemory();
  // Validate the optional size output before any mutation, even on errors.
  if (required_size_ptr && !guest.GetWritableSpan(required_size_ptr, sizeof(be_u16)))
    return X_STATUS_ACCESS_VIOLATION;
  std::array<u8, 4> bytes{};
  u16 required_size = 0;
  X_STATUS result = ExGetXConfigSetting(category, setting,
                                       buffer ? bytes.data() : nullptr,
                                       buffer_size, &required_size);
  if (result == X_STATUS_SUCCESS && buffer && required_size) {
    if (required_size > bytes.size() || !guest.GetWritableSpan(buffer, required_size))
      return X_STATUS_ACCESS_VIOLATION;
    if (required_size_ptr &&
        u64{buffer} < u64{required_size_ptr} + sizeof(be_u16) &&
        u64{required_size_ptr} < u64{buffer} + required_size)
      return X_STATUS_INVALID_PARAMETER;
    if (!guest.CopyTo(buffer, std::as_bytes(std::span(bytes).first(required_size))))
      return X_STATUS_ACCESS_VIOLATION;
  }
  if (required_size_ptr && !guest.Store(required_size_ptr, be_u16{required_size}))
    return X_STATUS_ACCESS_VIOLATION;
  return result;
}

u32 ExSetXConfigSetting_entry(u16 category, u16 setting, u32 buffer, u32 buffer_size) {
  // Only the six supported non-security user preferences can be written.
  // Unknown categories/keys fail explicitly instead of accepting a no-op.
  if (category != 7) return X_STATUS_INVALID_PARAMETER_1;
  const auto pref = LookupConsolePreference(setting);
  if (!pref.setting) return X_STATUS_INVALID_PARAMETER_2;
  if (buffer_size != pref.bytes) return X_STATUS_INVALID_PARAMETER;
  if (!buffer) return X_STATUS_INVALID_PARAMETER_3;
  auto& guest = kernel::GetCurrent().GetGuestMemory();
  auto bytes = guest.GetReadOnlySpan(buffer, pref.bytes);
  if (!bytes) return X_STATUS_ACCESS_VIOLATION;
  u32 value = 0;
  for (auto byte : *bytes) value = (value << 8) | std::to_integer<u8>(byte);
  if (!ValidPreference(setting, value)) return X_STATUS_INVALID_PARAMETER;
  if (!pref.setting->Set(value)) return X_STATUS_INVALID_PARAMETER;
  return X_STATUS_SUCCESS;
}'''

def patch(sdk,tests):
    header=sdk/"include/rex/kernel/kernel_settings.h"
    path=sdk/"src/kernel/xboxkrnl/xboxkrnl_xconfig.cpp"
    test=sdk/"tests/unit/kernel/xam_test.cpp"
    h=replace(header.read_text(),"  KernelSettings();",PREFS+"\n  KernelSettings();")
    source=path.read_text()
    source=replace(source,"#include <rex/kernel/title_runtime.h>",
        "#include <rex/kernel/title_runtime.h>\n#include <rex/kernel/guest_memory.h>\n#include <array>\n#include <span>")
    source=replace(source,"namespace rex::kernel::xboxkrnl {",
        "namespace rex::kernel::xboxkrnl {\n"+HELPER)
    source=replace(source,'    default:\n      REX_KERNEL_STUB("XConfig category 0x{:04X}", category);',
        GET_CATEGORY+'    default:\n      REXKRNL_WARN("METRO_XCONFIG unsupported category=0x{:04X} setting=0x{:04X}", category, setting);')
    source=replace(source,OLD_EXPORT,NEW_EXPORT)
    source=replace(source,"REX_EXPORT_STUB(__imp__ExSetXConfigSetting);",
        "REX_EXPORT(__imp__ExSetXConfigSetting, rex::kernel::xboxkrnl::ExSetXConfigSetting_entry)")
    existing=test.read_text()
    if "metro_xconfig" in existing:raise ValueError("test already staged")
    outputs={header:h,path:source,test:existing+"\n"+tests.read_text()}
    for path,content in outputs.items():path.write_text(content)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    p.add_argument("--tests",type=Path,required=True)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    patch(a.sdk,a.tests)
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
if __name__=="__main__":main()
