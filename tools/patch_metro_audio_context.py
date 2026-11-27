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
    s=replace(s,"Result<u32> RegisterClient(u32 callback, u32 callback_arg);",
        """Result<u32> RegisterClient(u32 callback, u32 callback_arg,
                             bool direct_context = false);""")
    s=replace(s,"    bool refused_logged = false;",
        "    bool refused_logged = false;\n    bool direct_context = false;")
    files[p]=s
    p="src/kernel/apu.cpp";s=(sdk/p).read_text()
    s=replace(s,"client_callback_arg = clients_[index].wrapped_callback_arg;",
        """client_callback_arg = clients_[index].direct_context
                                  ? clients_[index].callback_arg
                                  : clients_[index].wrapped_callback_arg;""")
    s=replace(s,"Result<u32> APU::RegisterClient(u32 callback, u32 callback_arg) {",
        "Result<u32> APU::RegisterClient(u32 callback, u32 callback_arg, bool direct_context) {")
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
  // Publish the fully initialized slot before making credits available.
  semaphore->Release(static_cast<i32>(queued_frames_), nullptr);"""
    s=replace(s,old,new)
    s=replace(s,"  StateOf(runtime_).GetAddressSpace()->SystemHeapFree(clients_[index].wrapped_callback_arg);",
        """  if (clients_[index].wrapped_callback_arg)
    StateOf(runtime_).GetAddressSpace()->SystemHeapFree(clients_[index].wrapped_callback_arg);""")
    files[p]=s
    p="src/kernel/xboxkrnl/xboxkrnl_audio.cpp";s=(sdk/p).read_text()
    s=replace(s,"  auto index = apu->RegisterClient(callback, callback_arg);",
        """  // Original XAM 17559 caller at 819AC59C builds {callback, object}
  // on its stack. The verified callback at 819A5878 copies r3 into r31,
  // then accesses object+304 and writes object+300 with no indirection.
  // Scope the ABI correction to this exact original registration path.
  const auto* thread = KernelThread::GetCallingThread();
  const u32 lr = thread && thread->GetThreadState()
      ? static_cast<u32>(thread->GetThreadState()->GetContext()->lr) : 0;
  const bool direct_context = callback == 0x819A5878u && lr == 0x819AC5A0u &&
                              kernel::GetCurrent().FindFunction(callback);
  if (direct_context)
    REXKRNL_INFO("METRO_AUDIO direct_context callback={:08X} object={:08X}", callback, callback_arg);
  auto index = apu->RegisterClient(callback, callback_arg, direct_context);""")
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
