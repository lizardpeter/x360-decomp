#!/usr/bin/env python3
"""Run original system-module process attach in the real hosted system KPROCESS."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

def replace(source,old,new):
    if source.count(old)!=1 or new in source:
        raise ValueError("unexpected system process anchor: "+old[:100])
    return source.replace(old,new,1)

DECL = """
  // Synchronously execute a system DLL's real process-attach entry in a
  // kernel thread belonging to the system process, not the title process.
  struct HostedSystemAttach {
    u64 entry_result;
    u32 bound_pads;
  };
  [[nodiscard]] Result<HostedSystemAttach> AttachHostedSystemModule(u32 address,
                                                                  u32 module_handle);
"""
BODY = r'''
Result<TitleRuntime::HostedSystemAttach> TitleRuntime::AttachHostedSystemModule(
    u32 address, u32 module_handle) {
  if (!IsLoaded() || !KernelThread::IsInThread() || !module_handle)
    return Err<HostedSystemAttach>(StatusError(X_STATUS_INVALID_PARAMETER));
  auto* caller = KernelThread::GetCallingThread();
  if (!caller || &caller->GetRuntime()!=this)
    return Err<HostedSystemAttach>(StatusError(X_STATUS_INVALID_PARAMETER));
  auto* dispatcher = state_->GetFunctionDispatcher();
  if (!dispatcher || !dispatcher->GetFunction(address))
    return Err<HostedSystemAttach>(StatusError(X_STATUS_INVALID_PARAMETER));
  const u32 system_process=state_->GetSystemProcess();
  if (!system_process)
    return Err<HostedSystemAttach>(StatusError(X_STATUS_UNSUCCESSFUL));
  struct Completion {
    HostedSystemAttach value{};
    std::atomic<bool> done{false};
  };
  // The worker owns its result even if the waiting title is stopped.
  auto completion=std::make_shared<Completion>();
  auto worker=std::make_unique<KernelThread>(*this,0,0,
    [this,dispatcher,completion,address,module_handle,system_process]() -> int {
      auto* current=KernelThread::GetCallingThread();
      auto* thread=current->GetGuestObject<X_KTHREAD>();
      if (!thread || static_cast<u32>(thread->process)!=system_process ||
          thread->process_type!=kXProcTypeSystem)
        return 1;
      REXSYS_INFO("METRO_SYSTEM_ATTACH process={:08X} type={} entry={:08X}",
                  system_process,static_cast<u32>(thread->process_type),address);
      u64 args[]={module_handle,1,0};
      completion->value.entry_result=dispatcher->Execute(current->GetThreadState(),address,args,3);
      if (static_cast<u32>(completion->value.entry_result)!=0 &&
          completion->value.entry_result!=0xDEADBABE)
        completion->value.bound_pads=AnnounceHostedPads();
      completion->done.store(true,std::memory_order_release);
      return 0;
    },system_process,true);
  auto launched=GetThreadRegistry().Launch(std::move(worker));
  if (!launched) return Err<HostedSystemAttach>(launched.error());
  const auto handle=*launched;
  // No retry and no fallback to the title process. A stalled attach is a
  // boot failure; the runtime's ordinary stop path owns worker teardown.
  u64 timeout=static_cast<u64>(-30LL*10000000LL);
  const auto waited=GetThreadRegistry().GetObjectWaiter().WaitGuestObject(handle,0,0,0,&timeout);
  CloseOwned(GetObjectTable(),handle);
  if (waited!=X_STATUS_SUCCESS)
    return Err<HostedSystemAttach>(StatusError(waited));
  if (!completion->done.load(std::memory_order_acquire))
    return Err<HostedSystemAttach>(StatusError(X_STATUS_UNSUCCESSFUL));
  return completion->value;
}
'''

def patch_sources(sdk,tests):
    header=sdk/"include/rex/kernel/object/kernel_thread.h"
    thread=sdk/"src/kernel/kernel_thread.cpp"
    public=sdk/"include/rex/kernel/title_runtime.h"
    runtime=sdk/"src/kernel/title_runtime.cpp"
    test=sdk/"tests/unit/kernel/xam_input_test.cpp"
    out={}
    out[header]=replace(header.read_text(),
        "               rex::MoveOnlyFunction<int()> host_fn);",
        "               rex::MoveOnlyFunction<int()> host_fn, u32 process = 0,\n               bool guest_thread = false);")
    out[thread]=replace(thread.read_text(),
        "                           rex::MoveOnlyFunction<int()> host_fn)\n    : KernelThread(runtime, stack_size, 0, 0, 0, creation_flags, false) {",
        "                           rex::MoveOnlyFunction<int()> host_fn, u32 process, bool guest_thread)\n    : KernelThread(runtime, stack_size, 0, 0, 0, creation_flags, guest_thread, false, process) {")
    out[public]=replace(public.read_text(),"  GuestMemory& GetGuestMemory() const;",
                        "  GuestMemory& GetGuestMemory() const;\n"+DECL)
    source=replace(runtime.read_text(),"#include <format>",
        "#include <format>\n#include <atomic>\n#include <rex/kernel/object/kernel_thread.h>\n#include <rex/kernel/object/object_table.h>\n#include <rex/kernel/thread_registry.h>\n#include <rex/kernel/types/thread.h>")
    out[runtime]=replace(source,"GuestMemory& TitleRuntime::GetGuestMemory() const {",
                         BODY+"\nGuestMemory& TitleRuntime::GetGuestMemory() const {")
    old=test.read_text()
    if "metro_system_attach" in old:raise ValueError("tests already staged")
    out[test]=old+"\n"+tests.read_text()
    return out

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    p.add_argument("--tests",type=Path,required=True)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    for path,content in patch_sources(a.sdk,a.tests).items():path.write_text(content)
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
if __name__=="__main__":main()
