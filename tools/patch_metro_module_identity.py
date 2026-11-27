#!/usr/bin/env python3
"""Keep guest dynamic XAM lookup on the verified retail instance, not the SDK shim."""
import argparse
from pathlib import Path
import subprocess
from patch_rexglue_imports import REVISION

def replace(source, old, new):
    if source.count(old) != 1:
        raise ValueError("unexpected module identity anchor: " + old[:100])
    return source.replace(old, new, 1)

RUNTIME = r'''
bool TitleRuntime::SelectRetailXam(u32 handle) {
  if (!IsLoaded() || IsRunning() || !handle || state_->retail_xam_hmodule) return false;
  auto& registry = GetModuleRegistry();
  const auto user = registry.FindUserModule("xam.xex");
  const auto kernel = registry.FindKernelModule("xam");
  if (!user || *user != handle || !kernel || *kernel == handle) return false;
  auto object = GetObjectTable().Get<ModuleObject>(handle);
  if (!object || object->type != ModuleType::kUser || !object->GetXEX() ||
      !object->hmodule_ptr || !object->user.is_dll_module ||
      !FindFunction(object->user.entry_point)) return false;
  // The caller owns the original load reference; guest unload must not
  // consume it. SDK-internal registry lookups remain unchanged.
  state_->retail_xam_hmodule = object->hmodule_ptr;
  return true;
}

bool TitleRuntime::IsSelectedRetailXamName(std::string_view name) const {
  if (!state_->retail_xam_hmodule) return false;
  for (const auto alias : {"xam", "xam.xex", "game:\\xam.xex",
                           "flash:\\xam.xex", "\\Device\\Flash\\xam.xex",
                           "\\SystemRoot\\xam.xex"}) {
    if (rex::string::utf8_equal_case(name, alias)) return true;
  }
  return false;
}

u32 TitleRuntime::FindGuestModule(std::string_view name) {
  auto& registry = GetModuleRegistry();
  if (!IsSelectedRetailXamName(name)) return registry.GetModule(name).value_or(0);
  const auto handle = registry.FindUserModule("xam.xex");
  if (!handle) return 0;
  auto object = GetObjectTable().Get<ModuleObject>(*handle);
  return object && object->hmodule_ptr == state_->retail_xam_hmodule ? *handle : 0;
}
'''

def patch(sdk):
    files={}
    def read(path):
        return (sdk/path).read_text()
    p="include/rex/kernel/title_runtime.h"
    s=read(p)
    s=replace(s,"#include <memory>","#include <memory>\n#include <string_view>")
    files[p]=replace(s,"  kernel::IModuleRegistry& GetModuleRegistry();",
        """  kernel::IModuleRegistry& GetModuleRegistry();

  /** Select a verified loaded retail XAM before launch. The original load reference stays pinned. */
  bool SelectRetailXam(u32 handle);
  bool IsSelectedRetailXamName(std::string_view name) const;
  /** Resolve a guest loader request, without changing internal SDK module resolution. */
  u32 FindGuestModule(std::string_view name);""")
    p="src/kernel/title_state.h"
    files[p]=replace(read(p),"  std::atomic<u32> audio_submit_logs{0};",
                     "  std::atomic<u32> audio_submit_logs{0};\n  u32 retail_xam_hmodule = 0;")
    p="src/kernel/title_state.cpp"
    files[p]=replace(read(p),"  StopThreads();\n  DetachSystems();",
                     "  StopThreads();\n  retail_xam_hmodule = 0;\n  DetachSystems();")
    p="src/kernel/title_runtime.cpp"
    s=read(p)
    s=replace(s,"#include <rex/kernel/object/object.h>",
        "#include <rex/kernel/object/object.h>\n#include <rex/kernel/object/module_object.h>\n#include <rex/kernel/object/object_table.h>\n#include <rex/kernel/module.h>\n#include <rex/string/text.h>")
    anchor="kernel::IModuleRegistry& TitleRuntime::GetModuleRegistry() {\n  return state_->GetModuleRegistry();\n}"
    files[p]=replace(s,anchor,anchor+"\n"+RUNTIME)
    p="src/kernel/xboxkrnl/xboxkrnl_xex.cpp"
    s=read(p)
    s=replace(s,"kernel::GetCurrent().GetModuleRegistry().GetModule(module_name.GetValue()).value_or(0)",
                "kernel::GetCurrent().FindGuestModule(module_name.GetValue())")
    s=replace(s,"modules.GetModule(module_name.GetValue()).value_or(0)",
                "runtime.FindGuestModule(module_name.GetValue())")
    s=replace(s,"  if (!hmodule) {\n    auto loaded = modules.LoadUserModule(module_name.GetValue());",
        """  if (!hmodule && runtime.IsSelectedRetailXamName(module_name.GetValue())) {
    *hmodule_ptr = 0;
    return X_STATUS_INVALID_HANDLE;
  }

  if (!hmodule) {
    auto loaded = modules.LoadUserModule(module_name.GetValue());""")
    s=replace(s,"    last_ref = (--ldr_data->load_count == 0);",
        """    // The system instance is owned by the title startup, not by the
    // guest dynamic-load reference. Preserve that reference until shutdown.
    if (hmodule.GetGuestAddress() == StateOf(kernel::GetCurrent()).retail_xam_hmodule &&
        ldr_data->load_count <= 1) return X_STATUS_SUCCESS;
    if (!ldr_data->load_count) return X_STATUS_INVALID_HANDLE;
    last_ref = (--ldr_data->load_count == 0);""")
    files[p]=s
    for p,s in files.items():
        (sdk/p).write_text(s)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    patch(a.sdk)
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
if __name__=="__main__":main()
