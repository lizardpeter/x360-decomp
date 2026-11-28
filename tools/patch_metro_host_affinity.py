#!/usr/bin/env python3
"""Keep six virtual PPC CPU identities distinct from sparse host CPU masks."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

def replace(source,old,new):
    if source.count(old)!=1:raise ValueError("host affinity anchor "+old[:80])
    return source.replace(old,new,1)

def patch(sdk,tests):
    h=sdk/"include/rex/platform/thread.h"
    posix=sdk/"src/base/threading_posix.cpp"
    win=sdk/"src/base/threading_win.cpp"
    common=sdk/"src/base/threading.cpp"
    kernel=sdk/"src/kernel/kernel_thread.cpp"
    test=sdk/"tests/unit/base/thread_priority_test.cpp"
    outputs={}
    outputs[h]=replace(h.read_text(),"REX_API u32 GetLogicalProcessorCount();", """REX_API u32 GetLogicalProcessorCount();

// Host CPU numbers may be sparse (cpuset restrictions), and the first
// 64 processor bits are the maximum represented by Thread::SetAffinityMask.
// Zero means that a usable host mask cannot be obtained; don't pin.
REX_API u64 GetAvailableProcessorMask();

// Preserve guest CPU identity but select the nth allowed host processor.
// On a host with fewer than six representable allowed processors, leave
// scheduling to the OS instead of forcing all guest workers onto one CPU.
constexpr u64 MapGuestProcessor(u64 allowed, u32 guest_cpu) {
  if (guest_cpu >= 6) return 0;
  u64 remaining = allowed;
  u32 count = 0;
  for (; remaining; remaining &= remaining - 1) ++count;
  if (count < 6) return 0;
  for (u32 i = 0; i < guest_cpu; ++i) allowed &= allowed - 1;
  return allowed & (u64{0} - allowed);
}""")
    outputs[posix]=replace(posix.read_text(),"void WidenProcessAffinity() {}", """void WidenProcessAffinity() {}

u64 GetAvailableProcessorMask() {
#if defined(__APPLE__)
  return 0;  // pthread affinity masks are not supported here.
#else
  cpu_set_t available;
  CPU_ZERO(&available);
  // Query the thread-group leader, not a guest worker that may have
  // inherited the creator's deliberately narrowed thread affinity.
  if (sched_getaffinity(getpid(), sizeof(available), &available) != 0) return 0;
  u64 result = 0;
  for (int i = 0; i < std::min(CPU_SETSIZE, 64); ++i)
    if (CPU_ISSET(i, &available)) result |= u64{1} << i;
  return result;
#endif
}""")
    outputs[posix]=replace(outputs[posix],"      auto set = CPU_ISSET(i, &cpu_set);\n      result |= set << i;",
        "      if (CPU_ISSET(i, &cpu_set)) result |= u64{1} << i;")
    outputs[win]=replace(win.read_text(),"u32 GetCallerSystemThreadID() {", """u64 GetAvailableProcessorMask() {
  DWORD_PTR process_mask=0, system_mask=0;
  if (!GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask)) return 0;
  return static_cast<u64>(process_mask & system_mask);
}

u32 GetCallerSystemThreadID() {""")
    outputs[common]=replace(common.read_text(),"""  static u32 value = 0;
  if (!value) {
    value = std::thread::hardware_concurrency();
  }
  return value;""","""  static const u32 value = std::thread::hardware_concurrency();
  return value;""")
    outputs[kernel]=replace(kernel.read_text(),"""  if (rex::platform::GetLogicalProcessorCount() >= 6) {
    if (!GetRuntimeSettings().ignore_thread_affinities.Get()) {
      thread_->SetAffinityMask(static_cast<u64>(1) << cpu_index);
    }
  } else {
    static log::OncePerKey<1> too_few_cores_once;
    REXSYS_WARN_ONCE(too_few_cores_once, 0, "Too few processor cores - scheduling will be wonky");
  }""","""  if (!GetRuntimeSettings().ignore_thread_affinities.Get()) {
    const auto allowed=rex::platform::GetAvailableProcessorMask();
    const auto target=rex::platform::MapGuestProcessor(allowed,cpu_index);
    if (target) {
      thread_->SetAffinityMask(target);
    } else {
      static log::OncePerKey<1> too_few_cores_once;
      REXSYS_WARN_ONCE(too_few_cores_once,0,
          "No six-CPU host affinity map (mask={:016X}); using OS scheduler",allowed);
    }
  }""")
    outputs[test]=test.read_text()+"\n"+tests.read_text()
    for p,source in outputs.items():p.write_text(source)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("sdk",type=Path)
    p.add_argument("--tests",type=Path,required=True)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    patch(a.sdk,a.tests)
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)

if __name__=="__main__":main()
