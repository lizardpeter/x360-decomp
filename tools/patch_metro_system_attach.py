#!/usr/bin/env python3
"""Run original system-module process attach in the real hosted system KPROCESS."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

def replace(source,old,new):
    if source.count(old)!=1 or (new and new in source):
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
  struct OwnedHandle {
    IObjectTable& table;
    X_HANDLE handle;
    ~OwnedHandle() { CloseOwned(table,handle); }
  } owned{GetObjectTable(),handle};
  // No retry and no fallback to the title process. A stalled attach is a
  // boot failure; the runtime's ordinary stop path owns worker teardown.
  u64 timeout=static_cast<u64>(-30LL*10000000LL);
  const auto waited=GetThreadRegistry().GetObjectWaiter().WaitGuestObject(handle,0,0,0,&timeout);
  if (waited!=X_STATUS_SUCCESS) {
    if (auto thread=GetThreadRegistry().FindByHandle(handle)) thread->RequestStop();
    return Err<HostedSystemAttach>(StatusError(waited));
  }
  if (!completion->done.load(std::memory_order_acquire))
    return Err<HostedSystemAttach>(StatusError(X_STATUS_UNSUCCESSFUL));
  return completion->value;
}
'''


def patch_thread_creation(source):
    source=replace(source,"#include <rex/kernel/types/thread.h>",
                   "#include <rex/kernel/types/thread.h>\n#include <rex/kernel/guest_memory.h>")
    start=source.index("u32 ExCreateThread_entry(")
    end=source.index("u32 ExTerminateThread_entry(",start)
    body=source[start:end]
    body=replace(body,"  auto& runtime = kernel::GetCurrent();",
        """  auto& runtime = kernel::GetCurrent();
  auto& memory = runtime.GetGuestMemory();
  const u32 handle_out = handle_ptr.GetGuestAddress();
  const u32 id_out = thread_id_ptr.GetGuestAddress();
  if ((handle_out && !memory.GetWritableSpan(handle_out,4)) ||
      (id_out && !memory.GetWritableSpan(id_out,4)))
    return X_STATUS_ACCESS_VIOLATION;
  if (handle_out && id_out && u64{handle_out}<u64{id_out}+4 &&
      u64{id_out}<u64{handle_out}+4)
    return X_STATUS_INVALID_PARAMETER;""")
    body=replace(body,"  KernelThread* raw = thread.get();\n\n","")
    a=body.index("  const u32 thread_id = raw->GetThreadID();")
    b=body.index("  REXKRNL_TRACE(",a)
    body=body[:a]+"""  auto& table=runtime.GetObjectTable();
  auto created=runtime.GetThreadRegistry().FindByHandle(handle);
  if (!created) {
    CloseOwned(table,handle);
    return X_STATUS_INVALID_HANDLE;
  }
  const u32 thread_id=created->GetThreadID();
  if (handle_out && (creation_flags & 0x80)) {
    // The retail kernel returns an owned KTHREAD pointer, not a handle,
    // for this creation flag. The hidden creation handle must not keep
    // the object alive after the guest releases its pointer reference.
    auto object=table.Get(handle);
    if (!object || object.GetGuestAddress()!=created->GetGuestObject()) {
      CloseOwned(table,handle);
      return X_STATUS_INVALID_HANDLE;
    }
    auto referenced=table.Reference(object);
    if (!referenced) {
      CloseOwned(table,handle);
      return ToXStatus(referenced);
    }
    *handle_ptr=created->GetGuestObject();
    CloseOwned(table,handle);
  } else if (handle_out) {
    *handle_ptr=handle;
  } else {
    CloseOwned(table,handle);
  }
  if (id_out) *thread_id_ptr=thread_id;
"""+body[b:]
    return source[:start]+body+source[end:]



def patch_thread_identity(source):
    source=replace(source,"  if (handle == 0xFFFFFFFE) {\n    return KernelThread::IsInThread() ? KernelThread::GetCurrentThreadHandle() : 0;\n  }","  if (handle == 0xFFFFFFFE) return 0; // never a real handle slot")
    source=replace(source,"  if (handle < kHandleBase) {","  if (handle < kHandleBase || (handle & 3)) {")
    source=replace(source,"Result<X_HANDLE> ObjectTable::Duplicate(X_HANDLE handle) {\n  handle = Translate(handle);",
        """Result<X_HANDLE> ObjectTable::Duplicate(X_HANDLE handle) {
  if (handle == 0xFFFFFFFE) {
    auto current=Get(handle);
    if (!current) return Err<X_HANDLE>(StatusError(X_STATUS_INVALID_HANDLE));
    return Open(current);
  }
  handle = Translate(handle);""")
    source=replace(source,"ObjectPin ObjectTable::Get(X_HANDLE handle) {\n  handle = Translate(handle);",
        """ObjectPin ObjectTable::Get(X_HANDLE handle) {
  if (handle == 0xFFFFFFFE) {
    if (!KernelThread::IsInThread()) return {};
    auto* current=KernelThread::GetCallingThread();
    if (!current || &current->GetRuntime()!=owner_) return {};
    // The guest thread holds its own object reference until exit, even
    // when every user-visible handle (or the pointer-returning creation
    // handle) has been closed. Numeric handle slots can be reused.
    return GetByAddress(current->GetGuestObject());
  }
  handle = Translate(handle);""")
    return source

def patch_completion_identity(header,source):
    header=replace(header,"void CompleteOverlappedEx(u32 overlapped, X_RESULT result, u32 extended_error, u32 length);",
        "void CompleteOverlappedEx(u32 overlapped, X_RESULT result, u32 extended_error, u32 length,\n                            u32 submitting_thread_id);")
    source=replace(source,"                                      u32 length) {\n  auto ptr",
        "                                      u32 length, u32 submitting_thread_id) {\n  auto ptr")
    source=replace(source,"    X_HANDLE thread_handle = XOverlappedGetContext(ptr);\n    auto thread = runtime_.GetThreadRegistry().FindByHandle(thread_handle);",
        """    // Completion belongs to the original submitting thread, not a
    // possibly recycled handle slot. The ID is captured by the host when
    // the request is queued, rather than reread from guest memory.
    auto thread = runtime_.GetThreadRegistry().Find(submitting_thread_id);""")
    source=replace(source,"  XOverlappedSetContext(ptr, KernelThread::GetCurrentThreadHandle());\n  CompleteOverlappedEx(overlapped, options.result, ExtendedError(options), Length(options));",
        """  auto* submitting=KernelThread::GetCallingThread();
  const u32 id=submitting ? submitting->GetThreadID() : 0;
  XOverlappedSetContext(ptr,id); // reserved system context, no handle ownership
  CompleteOverlappedEx(overlapped, options.result, ExtendedError(options), Length(options),id);""")
    source=replace(source,"  XOverlappedSetContext(ptr, KernelThread::GetCurrentThreadHandle());\n  std::lock_guard lock(dispatch_mutex_);",
        """  auto* submitting=KernelThread::GetCallingThread();
  const u32 id=submitting ? submitting->GetThreadID() : 0;
  XOverlappedSetContext(ptr,id);
  std::lock_guard lock(dispatch_mutex_);""")
    source=replace(source,"dispatch_queue_.push_back([this, work = std::move(work), overlapped, pre = std::move(pre),",
        "dispatch_queue_.push_back([this, work = std::move(work), overlapped, id, pre = std::move(pre),")
    source=replace(source,"    CompleteOverlappedEx(overlapped, options.result, ExtendedError(options), Length(options));",
        "    CompleteOverlappedEx(overlapped, options.result, ExtendedError(options), Length(options),id);")
    return header,source


def patch_sources(sdk,tests):
    header=sdk/"include/rex/kernel/object/kernel_thread.h"
    thread=sdk/"src/kernel/kernel_thread.cpp"
    public=sdk/"include/rex/kernel/title_runtime.h"
    runtime=sdk/"src/kernel/title_runtime.cpp"
    test=sdk/"tests/unit/kernel/xam_input_test.cpp"
    exports=sdk/"src/kernel/xboxkrnl/xboxkrnl_threading.cpp"
    table=sdk/"src/kernel/object_table.cpp"
    dispatcher_h=sdk/"src/kernel/dispatcher.h"
    dispatcher_cpp=sdk/"src/kernel/dispatcher.cpp"
    out={}
    out[exports]=patch_thread_creation(exports.read_text())
    out[table]=patch_thread_identity(table.read_text())
    out[dispatcher_h],out[dispatcher_cpp]=patch_completion_identity(dispatcher_h.read_text(),dispatcher_cpp.read_text())
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
