#!/usr/bin/env python3
"""Install a per-title native pad provider bridge for original XAM."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

def replace(source,old,new):
    if source.count(old)!=1 or new in source:
        raise ValueError("unexpected input bridge anchor: "+old[:100])
    return source.replace(old,new,1)

FIELDS="  // Device context ownership belongs to the attached title, not the host process.\n  rex::hid::IInputSystem* hosted_pad_input = nullptr;\n  std::atomic<u32> hosted_pad_binding_callback{0};\n  // 0=unannounced, 1=inside binding callback, 2=bound.\n  std::array<std::atomic<u8>, rex::hid::IInputSystem::kMaxUsers> hosted_pad_state{};\n  std::array<std::atomic<u8>, rex::hid::IInputSystem::kMaxUsers> hosted_pad_port{};\n  void ResetHostedPadBindings() {\n    hosted_pad_input = nullptr;\n    hosted_pad_binding_callback.store(0);\n    for (auto& slot : hosted_pad_state) slot.store(0);\n    for (auto& slot : hosted_pad_port) slot.store(0xff);\n  }\n"
BODY="namespace {\nconstexpr u32 kHostedContextBase = 0x10000001;\nconstexpr u32 kNotConnected = 0xC000009D; // original XAM's disconnected-device status\n\nstd::optional<u32> HostedPadSlot(TitleState& state, u32 context) {\n  if (context < kHostedContextBase) return std::nullopt;\n  const u32 user = context - kHostedContextBase;\n  if (!state.hosted_pad_input || user >= state.hosted_pad_state.size() ||\n      !state.hosted_pad_state[user].load(std::memory_order_acquire)) return std::nullopt;\n  return user;\n}\n\nstruct OutputRange { u32 address; u32 size; bool required; };\nbool CheckOutputs(GuestMemory& memory, std::initializer_list<OutputRange> ranges) {\n  for (auto a = ranges.begin(); a != ranges.end(); ++a) {\n    if (!a->address) {\n      if (a->required) return false;\n      continue;\n    }\n    if (!memory.GetWritableSpan(a->address, a->size)) return false;\n    for (auto b = ranges.begin(); b != a; ++b)\n      if (b->address && u64{a->address} < u64{b->address} + b->size &&\n          u64{b->address} < u64{a->address} + a->size) return false;\n  }\n  return true;\n}\n} // namespace\n\nvoid DrvSetUserBindingCallback_entry(u32 callback) {\n  auto& state = kernel::GetCurrentState();\n  if (callback && !state.GetFunctionDispatcher()->GetFunction(callback)) {\n    REXKRNL_WARN(\"METRO_INPUT rejected unmapped binding callback {:08X}\", callback);\n    return;\n  }\n  state.hosted_pad_binding_callback.store(callback, std::memory_order_release);\n  REXKRNL_INFO(\"METRO_INPUT binding_callback={:08X}\", callback);\n}\n\nu32 XInputdGetCapabilities_entry(u32 context, u32 caps, u32 extra) {\n  auto& state = kernel::GetCurrentState();\n  auto user = HostedPadSlot(state, context);\n  if (!user) return kNotConnected;\n  auto& memory = state.GetGuestMemory();\n  if (!CheckOutputs(memory, {{caps, sizeof(rex::xam::X_INPUT_CAPABILITIES), true},\n                             {extra, 4, false}})) return X_STATUS_ACCESS_VIOLATION;\n  auto result = state.hosted_pad_input->GetCapabilities(*user);\n  if (!result) return kNotConnected;\n  const auto value = rex::xam::ToXInputCapabilities(*result);\n  if (!memory.Store(caps, value)) return X_STATUS_ACCESS_VIOLATION;\n  // The hosted provider has no auxiliary physical-controller condition to\n  // report. 17559 inspects this separate DWORD even on successful queries.\n  if (extra && !memory.Store(extra, be_u32{0})) return X_STATUS_ACCESS_VIOLATION;\n  return X_STATUS_SUCCESS;\n}\n\nu32 XInputdReadState_entry(u32 context, u32 packet, u32 gamepad, u32 extra) {\n  auto& state = kernel::GetCurrentState();\n  auto user = HostedPadSlot(state, context);\n  if (!user) return kNotConnected;\n  auto& memory = state.GetGuestMemory();\n  if (!CheckOutputs(memory, {{packet, 4, false},\n                             {gamepad, sizeof(rex::xam::X_INPUT_GAMEPAD), true},\n                             {extra, 4, false}})) return X_STATUS_ACCESS_VIOLATION;\n  auto reading = state.hosted_pad_input->GetState(*user);\n  if (!reading) return kNotConnected;\n  const auto value = rex::xam::ToXInputState(*reading);\n  if (!memory.Store(gamepad, value.gamepad) ||\n      (packet && !memory.Store(packet, value.packet_number)) ||\n      (extra && !memory.Store(extra, be_u32{0}))) return X_STATUS_ACCESS_VIOLATION;\n  return X_STATUS_SUCCESS;\n}\n"
RUNTIME="namespace rex::kernel {\nu32 TitleRuntime::AnnounceHostedPads() {\n  auto* thread = KernelThread::GetCallingThread();\n  if (!thread || &thread->GetRuntime() != this) return 0;\n  auto& state = StateOf(*this);\n  auto* input = state.hosted_pad_input;\n  auto* dispatcher = state.GetFunctionDispatcher();\n  const u32 callback = state.hosted_pad_binding_callback.load(std::memory_order_acquire);\n  if (!input || !dispatcher || !callback || !dispatcher->GetFunction(callback)) return 0;\n  auto& memory = GetGuestMemory();\n  u32 total = 0;\n  for (u32 user = 0; user < state.hosted_pad_state.size(); ++user) {\n    auto& slot = state.hosted_pad_state[user];\n    if (slot.load(std::memory_order_acquire) == 2) { ++total; continue; }\n    auto caps = input->GetCapabilities(user);\n    if (!caps || caps->subtype == 0) continue;\n    u8 previous = 0;\n    if (!slot.compare_exchange_strong(previous, 1, std::memory_order_acq_rel)) continue;\n    const auto port = memory.Allocate(4, 16, GuestProtect::kReadWrite, GuestHeap::kSystem);\n    if (!port) { slot.store(0); continue; }\n    if (!memory.Store(*port, u8{0xff})) {\n      (void)memory.Free(*port);\n      slot.store(0);\n      continue;\n    }\n    // The original binding callback owns port selection and guest bookkeeping.\n    // Contexts are stable opaque IDs for hosted pads, not guest pointers.\n    const u32 context = 0x10000001 + user;\n    u64 args[] = {context, context, 0, 0, *port};\n    const u64 status = dispatcher->Execute(thread->GetThreadState(), callback, args, 5);\n    const auto assigned = memory.Load<u8>(*port);\n    (void)memory.Free(*port);\n    if (status == 0 && assigned && *assigned < state.hosted_pad_state.size()) {\n      state.hosted_pad_port[user].store(*assigned, std::memory_order_release);\n      slot.store(2, std::memory_order_release);\n      ++total;\n      REXKRNL_INFO(\"METRO_INPUT bound context={:08X} host_user={} guest_port={}\",\n                    context, user, static_cast<u32>(*assigned));\n    } else {\n      state.hosted_pad_port[user].store(0xff);\n      slot.store(0, std::memory_order_release);\n      REXKRNL_WARN(\"METRO_INPUT bind failed context={:08X} result={:08X}\",\n                    context, static_cast<u32>(status));\n    }\n  }\n  return total;\n}\n} // namespace rex::kernel\n"
BODY += "\nu32 XInputdGetDeviceStats_entry(u32 context, [[maybe_unused]] u32 query,\n                                [[maybe_unused]] u32 output,\n                                [[maybe_unused]] u32 extra) {\n  auto& state = kernel::GetCurrentState();\n  auto user = HostedPadSlot(state, context);\n  if (!user) return kNotConnected;\n  // The hosted pad API exposes state, capabilities and identity, not the\n  // retail driver statistics structure. 17559 tests the sign of r3 and\n  // treats the old positive opaque context as success. Never publish\n  // success with an uninitialized or guessed output structure.\n  return X_STATUS_NOT_SUPPORTED;\n}\n"
EXPORTS=("DrvSetUserBindingCallback","XInputdGetCapabilities","XInputdReadState","XInputdGetDeviceStats")

def patch_sources(sdk,tests):
    h=sdk/"src/kernel/title_state.h"
    cpp=sdk/"src/kernel/title_state.cpp"
    public=sdk/"include/rex/kernel/title_runtime.h"
    hid=sdk/"src/kernel/xboxkrnl/xboxkrnl_hid.cpp"
    test=sdk/"tests/unit/kernel/xam_input_test.cpp"
    outputs={}
    old="  std::atomic<u32> audio_submit_logs{0};"
    outputs[h]=replace(h.read_text(),old,old+"\n"+FIELDS)
    source=cpp.read_text()
    old="  xam_->AttachSystems(ui_, input, video_mode_);"
    source=replace(source,old,old+"\n  hosted_pad_input = input;")
    old="  attached_ = false;\n}"
    outputs[cpp]=replace(source,old,"  ResetHostedPadBindings();\n"+old)
    old="  GuestMemory& GetGuestMemory() const;"
    outputs[public]=replace(public.read_text(),old,old+"\n\n  /** Announces connected hosted pads to a registered guest binding callback. Guest thread only. */\n  u32 AnnounceHostedPads();")
    source=hid.read_text()
    old="#include <rex/kernel/title_runtime.h>"
    source=replace(source,old,old+"\n#include <rex/kernel/guest_memory.h>\n#include <rex/kernel/function_dispatcher.h>\n#include <rex/kernel/object/kernel_thread.h>\n#include <initializer_list>\n#include <optional>\n#include \"kernel/title_state.h\"\n#include \"kernel/kernel.h\"\n#include \"kernel/categories.h\"\n#include \"xam/input_convert.h\"")
    old="}  // namespace rex::kernel::xboxkrnl"
    source=replace(source,old,BODY+"\n"+old+"\n\n"+RUNTIME)
    for name in EXPORTS:
        source=replace(source,"REX_EXPORT_STUB(__imp__"+name+");",
                       "REX_EXPORT(__imp__"+name+", rex::kernel::xboxkrnl::"+name+"_entry)")
    outputs[hid]=source
    source=test.read_text()
    if "metro_input_bridge" in source:raise ValueError("tests already staged")
    outputs[test]=source+"\n"+tests.read_text()
    return outputs

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    p.add_argument("--tests",type=Path,required=True)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    outputs=patch_sources(a.sdk,a.tests)
    for path,content in outputs.items():path.write_text(content)
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
if __name__=="__main__":main()
