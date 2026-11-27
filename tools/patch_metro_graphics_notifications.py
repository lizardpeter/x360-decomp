#!/usr/bin/env python3
"""Deliver the original 17559 XAM graphics notifications with audited payload ABI."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

def replace(source,old,new):
    if source.count(old)!=1 or (new and new in source):
        raise ValueError("unexpected graphics notification anchor: "+old[:100])
    return source.replace(old,new,1)

OLD="""u32 VdCallGraphicsNotificationRoutines_entry(u32 unk0,
                                             [[maybe_unused]] GuestPtrT<BufferScaling> args_ptr) {
  REX_ASSERT(unk0 == 1);

  return 0;
}"""

BODY=r"""
// Original 17559 XAM 816CE980 registers 816CBFD8. Its registration
// result is ignored; both verified callback cases overwrite or ignore r3.
// Do not guess a generic registration structure or an unobserved event ABI.
void VdRegisterXamGraphicsNotification_entry(u32 callback) {
  auto& state=kernel::GetCurrentState();
  if (!callback) {
    state.metro_xam_graphics_callback.store(0,std::memory_order_release);
    REXKRNL_INFO("METRO_GFX_NOTIFY registration cleared");
    return;
  }
  auto* dispatcher=state.GetFunctionDispatcher();
  if (!state.retail_xam_hmodule || callback!=0x816CBFD8u ||
      !dispatcher || !dispatcher->GetFunction(callback)) {
    REXKRNL_WARN("METRO_GFX_NOTIFY registration rejected callback={:08X}",callback);
    return;
  }
  state.metro_xam_graphics_callback.store(callback,std::memory_order_release);
  REXKRNL_INFO("METRO_GFX_NOTIFY registration callback={:08X}",callback);
}

u32 VdCallGraphicsNotificationRoutines_entry(u32 event,u32 payload) {
  // Six independently recovered original producers, split between XAM
  // and Metro. Event 1: four halfwords followed by 56 bytes. Event 9:
  // two DWORDs describing an original allocation (or its retirement).
  const u32 size=event==1?64u:event==9?8u:0u;
  if (!size) {
    REXKRNL_WARN("METRO_GFX_NOTIFY unsupported event={}",event);
    return X_STATUS_NOT_SUPPORTED;
  }
  auto& runtime=kernel::GetCurrent();
  auto& state=kernel::GetCurrentState();
  const u32 callback=state.metro_xam_graphics_callback.load(std::memory_order_acquire);
  // With no observer, there is nothing to deliver. In particular ordinary
  // titles using the hosted XAM retain the previous event-1 behavior.
  if (!callback) return X_STATUS_SUCCESS;
  if (!state.retail_xam_hmodule || state.IsTerminatingTitle())
    return X_STATUS_UNSUCCESSFUL;
  if (!payload || payload>UINT32_MAX-(size-1) ||
      !runtime.GetGuestMemory().GetReadOnlySpan(payload,size))
    return X_STATUS_ACCESS_VIOLATION;
  auto* thread=KernelThread::GetCallingThread();
  auto* dispatcher=state.GetFunctionDispatcher();
  if (!thread || &thread->GetRuntime()!=&runtime || !dispatcher ||
      !dispatcher->GetFunction(callback))
    return X_STATUS_UNSUCCESSFUL;
  if (state.metro_xam_graphics_callback.load(std::memory_order_acquire)!=callback)
    return X_STATUS_UNSUCCESSFUL;
  // The caller's payload is on its guest stack. Deliver synchronously and
  // do not retain the pointer, copy guessed fields or create a host UI.
  // The original registered XAM module is pinned until guest threads stop.
  // No host lock is held across guest execution. The two observed cases
  // do not consume r3 before overwriting it; use zero for this unused arg.
  u64 args[]={0,event,payload};
  REXKRNL_INFO("METRO_GFX_NOTIFY dispatch event={} bytes={} callback={:08X}",event,size,callback);
  dispatcher->Execute(thread->GetThreadState(),callback,args,3);
  REXKRNL_INFO("METRO_GFX_NOTIFY returned event={}",event);
  return X_STATUS_SUCCESS;
}
"""

def corrected_video(source):
    source=replace(source,"#include <rex/kernel/title_runtime.h>",
        "#include <rex/kernel/title_runtime.h>\n#include <rex/kernel/object/kernel_thread.h>\n#include <rex/kernel/guest_memory.h>")
    source=replace(source,"REX_EXPORT_STUB(__imp__VdRegisterXamGraphicsNotification);\n","")
    source=replace(source,OLD,BODY)
    anchor="REX_EXPORT(__imp__VdCallGraphicsNotificationRoutines,"
    return replace(source,anchor,"REX_EXPORT(__imp__VdRegisterXamGraphicsNotification, rex::kernel::xboxkrnl::VdRegisterXamGraphicsNotification_entry)\n"+anchor)

def patch(sdk,tests):
    video=sdk/"src/kernel/xboxkrnl/xboxkrnl_video.cpp"
    state=sdk/"src/kernel/title_state.h"
    lifecycle=sdk/"src/kernel/title_state.cpp"
    test=sdk/"tests/unit/kernel/files_test.cpp"
    updated=corrected_video(video.read_text())
    h=replace(state.read_text(),"  u32 retail_xam_hmodule = 0;",
        "  u32 retail_xam_hmodule = 0;\n  std::atomic<u32> metro_xam_graphics_callback{0};")
    cpp=replace(lifecycle.read_text(),"  retail_xam_hmodule = 0;\n  DetachSystems();",
        "  metro_xam_graphics_callback.store(0,std::memory_order_release);\n  retail_xam_hmodule = 0;\n  DetachSystems();")
    cpp=replace(cpp,"  ResetHostedPadBindings();",
        "  metro_xam_graphics_callback.store(0,std::memory_order_release);\n  ResetHostedPadBindings();")
    t=test.read_text()
    if "metro_graphics_notification" in t:raise ValueError("already staged graphics tests")
    for p,s in ((video,updated),(state,h),(lifecycle,cpp),(test,t+"\n"+tests.read_text())):
        p.write_text(s)

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
