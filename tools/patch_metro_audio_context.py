#!/usr/bin/env python3
"""Preserve the verified original XAM render callback's direct object argument."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

def replace(s,old,new):
    if s.count(old)!=1:raise ValueError("audio patch anchor: "+old[:100])
    return s.replace(old,new,1)

def patch(sdk,tests):
    files={}
    p="src/kernel/apu.h";s=(sdk/p).read_text()
    s=replace(s,"class XMADecoder;",
        """class XMADecoder;

enum class RetailRenderContext { kNone, kXam17559, kBootanim17559 };
// Match callback entry and exact loaded retail image layout. Generated direct
// calls need not preserve the guest LR at a host kernel export.
constexpr RetailRenderContext GetRetailRenderContext(u32 callback,u32 base,u32 size,u32 entry) {
  if (callback==0x819A5878u && base==0x815f0000u && size==0x610000u && entry==0x81696af0u)
    return RetailRenderContext::kXam17559;
  if (callback==0x9804BEA0u && base==0x98000000u && size==638976u && entry==0)
    return RetailRenderContext::kBootanim17559;
  return RetailRenderContext::kNone;
}""")
    s=replace(s,"Result<u32> RegisterClient(u32 callback, u32 callback_arg);",
        """Result<u32> RegisterClient(u32 callback, u32 callback_arg,
                             bool direct_context = false, u32 driver_out = 0);""")
    s=replace(s,"    bool refused_logged = false;",
        "    bool refused_logged = false;\n    bool direct_context = false;\n    bool in_flight = false;\n    bool retiring = false;")
    s=replace(s,"  void WorkerMain();","  void WorkerMain();\n  void FinishCallback(u32 index);")
    files[p]=s
    p="src/kernel/apu.cpp";s=(sdk/p).read_text()
    s=replace(s,"""        client_callback = clients_[index].callback;
        client_callback_arg = clients_[index].wrapped_callback_arg;""",
        """        auto& client=clients_[index];
        client_callback=client.in_use && !client.retiring ? client.callback : 0;
        client_callback_arg=client.direct_context ? client.callback_arg : client.wrapped_callback_arg;
        if (client_callback) {
          REX_ASSERT(!client.in_flight);
          client.in_flight=true;
        }""")
    s=replace(s,"""      if (client_callback) {
        REX_PROFILE_SCOPE_TEXT("apu", "rex::kernel::APU->client_callback");""",
        """      if (client_callback) {
        // Pin the slot through the entire original callback, including a
        // stop exception or a callback unregistering itself.
        rex::ScopeGuard pin([this,index] { FinishCallback(index); });
        REX_PROFILE_SCOPE_TEXT("apu", "rex::kernel::APU->client_callback");""")
    s=replace(s,"[](const Client& c) { return !c.in_use; }",
        "[](const Client& c) { return !c.in_use && !c.in_flight && !c.retiring; }")
    s=replace(s,"void APU::UnregisterClient(u32 index) {",
        """void APU::FinishCallback(u32 index) {
  std::lock_guard lock(mutex_);
  auto& client=clients_[index];
  REX_ASSERT(client.in_flight);
  client.in_flight=false;
  if (client.retiring) {
    if (client.wrapped_callback_arg)
      StateOf(runtime_).GetAddressSpace()->SystemHeapFree(client.wrapped_callback_arg);
    client={};
  }
}

void APU::UnregisterClient(u32 index) {""")

    s=replace(s,"Result<u32> APU::RegisterClient(u32 callback, u32 callback_arg) {",
        "Result<u32> APU::RegisterClient(u32 callback, u32 callback_arg, bool direct_context, u32 driver_out) {")
    old="""  semaphore->Release(static_cast<i32>(queued_frames_), nullptr);
  const u32 ptr = StateOf(runtime_).GetAddressSpace()->SystemHeapAlloc(0x4);
  *StateOf(runtime_).GetAddressSpace()->TranslateVirtual<be_u32*>(ptr) = callback_arg;
  *free = {*stream, callback, callback_arg, ptr, true};"""
    new="""  // The original retail system callback already receives its object body.
  // Preserve the legacy indirection for other callers, but do not allocate
  // a four-byte surrogate for a callback with a verified direct ABI.
  u32 ptr = 0;
  if (!direct_context) {
    ptr = StateOf(runtime_).GetAddressSpace()->SystemHeapAlloc(0x4);
    if (!ptr) {
      audio_->CloseStream(*stream);
      while (platform::Wait(semaphore, false, std::chrono::milliseconds(0)) ==
             platform::WaitResult::kSuccess) {}
      return Err<u32>(StatusError(X_STATUS_NO_MEMORY));
    }
    *StateOf(runtime_).GetAddressSpace()->TranslateVirtual<be_u32*>(ptr) = callback_arg;
  }
  *free = {*stream, callback, callback_arg, ptr, true, false, direct_context};
  // Publish the driver handle while the worker still holds off on the slot.
  if (driver_out)
    *StateOf(runtime_).GetAddressSpace()->TranslateVirtual<be_u32*>(driver_out) = 0x41550000u | index;
  // Publish the fully initialized slot before making credits available.
  semaphore->Release(static_cast<i32>(queued_frames_), nullptr);"""
    s=replace(s,old,new)
    s=replace(s,"""  audio_->CloseStream(clients_[index].stream);
  StateOf(runtime_).GetAddressSpace()->SystemHeapFree(clients_[index].wrapped_callback_arg);
  clients_[index] = {};
  platform::Semaphore* semaphore = semaphores_[index].get();
  while (platform::Wait(semaphore, false, std::chrono::milliseconds(0)) ==
         platform::WaitResult::kSuccess) {}""",
        """  auto& client=clients_[index];
  client.in_use=false;
  client.retiring=true;
  client.callback=0;
  audio_->CloseStream(client.stream);
  platform::Semaphore* semaphore = semaphores_[index].get();
  while (platform::Wait(semaphore, false, std::chrono::milliseconds(0)) ==
         platform::WaitResult::kSuccess) {}
  // No new invocation is dispatched. Existing callbacks may unregister
  // themselves, so do not wait on the worker while holding the APU lock.
  // Retain SDK-owned callback memory and reserve the index until it unwinds.
  if (!client.in_flight) {
    if (client.wrapped_callback_arg)
      StateOf(runtime_).GetAddressSpace()->SystemHeapFree(client.wrapped_callback_arg);
    client={};
  }""")
    files[p]=s
    p="src/kernel/xboxkrnl/xboxkrnl_audio.cpp";s=(sdk/p).read_text()
    s=replace(s,"  auto index = apu->RegisterClient(callback, callback_arg);",
        """  // Original XAM 17559 caller at 819AC59C builds {callback, object}
  // on its stack. The verified callback at 819A5878 copies r3 into r31,
  // then accesses object+304 and writes object+300 with no indirection.
  // Scope the ABI correction to this exact original registration path.
  auto* thread = KernelThread::GetCallingThread();
  const u32 lr = thread && thread->GetThreadState()
      ? static_cast<u32>(thread->GetThreadState()->GetContext()->lr) : 0;
  auto& runtime=kernel::GetCurrent();
  auto& registry=runtime.GetModuleRegistry();
  auto contract=kernel::RetailRenderContext::kNone;
  // The live 394ea8ba run reached the original callback but the LR-gated
  // correction never selected direct mode. Use actual mapped module identity,
  // not an assumed LR value at a compiled host import.
  for (const auto candidate : {registry.FindUserModule("xam.xex"),registry.FindUserModule("bootanim.xex"),
                               registry.GetExecutable()}) {
    if (!candidate)continue;
    auto module=runtime.GetObjectTable().Get<ModuleObject>(*candidate);
    const auto* xex=module?module->GetXEX():nullptr;
    if (!xex || !xex->IsExecutableAddress(callback))continue;
    contract=kernel::GetRetailRenderContext(callback,xex->GetBaseAddress(),
                                            xex->GetImageSize(),xex->GetEntryPoint());
    if (contract!=kernel::RetailRenderContext::kNone)break;
  }
  const bool direct_context=contract!=kernel::RetailRenderContext::kNone;
  const u32 output=driver_ptr.GetGuestAddress();
  if (!output || !runtime.GetGuestMemory().GetWritableSpan(output,4))
    return X_E_INVALIDARG;
  REXKRNL_INFO("METRO_AUDIO registration callback={:08X} argument={:08X} lr={:08X} direct={} output={:08X}",
                callback,callback_arg,lr,direct_context,output);
  if (direct_context) {
    // Both independently verified original callbacks access the direct object
    // through +304 and write +300. Refuse invalid contexts before queuing
    // any audio work; don't silently substitute the legacy wrapper.
    if (!runtime.FindFunction(callback) || !callback_arg ||
        callback_arg>0xffffffffu-308u ||
        !runtime.GetGuestMemory().GetReadOnlySpan(callback_arg,308) ||
        !runtime.GetGuestMemory().GetWritableSpan(callback_arg+300,4))
      return X_E_INVALIDARG;
    REXKRNL_INFO("METRO_AUDIO direct_context module={} callback={:08X} object={:08X}",
        contract==kernel::RetailRenderContext::kXam17559?"xam":"bootanim",callback,callback_arg);
  }
  auto index = apu->RegisterClient(callback, callback_arg, direct_context, output);""")
    s=replace(s,"#include <rex/kernel/title_runtime.h>","#include <rex/kernel/title_runtime.h>\n#include <rex/kernel/guest_memory.h>\n#include <rex/kernel/module.h>\n#include <rex/kernel/object/module_object.h>\n#include <rex/kernel/object/object_table.h>")
    s=replace(s,"  *driver_ptr = 0x41550000 | (*index & 0x0000FFFF);","  // APU publishes the output before scheduling the first callback.")
    s=replace(s,"""  if (!callback_ptr) {
    return X_E_INVALIDARG;
  }

  u32 callback = callback_ptr[0];""",
        """  auto& memory=kernel::GetCurrent().GetGuestMemory();
  const auto descriptor=callback_ptr.GetGuestAddress();
  if (!descriptor || descriptor>0xfffffff8u ||
      !memory.GetReadOnlySpan(descriptor,8))
    return X_E_INVALIDARG;
  u32 callback = callback_ptr[0];""")

    files[p]=s
    p="tests/unit/kernel/apu_test.cpp";s=(sdk/p).read_text()
    if "metro_audio_context" in s:raise ValueError("test already staged")
    files[p]=s+"\n"+tests.read_text()
    for p,s in files.items():(sdk/p).write_text(s)

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
