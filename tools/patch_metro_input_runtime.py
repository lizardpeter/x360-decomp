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

FIELDS="  // Device context ownership belongs to the attached title, not the host process.\n  rex::hid::IInputSystem* hosted_pad_input = nullptr;\n  std::atomic<u32> hosted_pad_binding_callback{0};\n  // 0=unannounced, 1=inside binding callback, 2=bound.\n  std::array<std::atomic<u8>, rex::hid::IInputSystem::kMaxUsers> hosted_pad_state{};\n  std::array<std::atomic<u8>, rex::hid::IInputSystem::kMaxUsers> hosted_pad_port{};\n  std::array<std::atomic<u16>, rex::hid::IInputSystem::kMaxUsers> hosted_pad_buttons{};\n  void ResetHostedPadBindings() {\n    hosted_pad_input = nullptr;\n    hosted_pad_binding_callback.store(0);\n    for (auto& slot : hosted_pad_state) slot.store(0);\n    for (auto& slot : hosted_pad_port) slot.store(0xff);\n    for (auto& buttons : hosted_pad_buttons) buttons.store(0);\n  }\n"
BODY="namespace {\nconstexpr u32 kHostedContextBase = 0x10000001;\nconstexpr u32 kNotConnected = 0xC000009D; // original XAM's disconnected-device status\n\nstd::optional<u32> HostedPadSlot(TitleState& state, u32 context) {\n  if (context < kHostedContextBase) return std::nullopt;\n  const u32 user = context - kHostedContextBase;\n  if (!state.hosted_pad_input || user >= state.hosted_pad_state.size() ||\n      !state.hosted_pad_state[user].load(std::memory_order_acquire)) return std::nullopt;\n  return user;\n}\n\nstruct OutputRange { u32 address; u32 size; bool required; };\nbool CheckOutputs(GuestMemory& memory, std::initializer_list<OutputRange> ranges) {\n  for (auto a = ranges.begin(); a != ranges.end(); ++a) {\n    if (!a->address) {\n      if (a->required) return false;\n      continue;\n    }\n    if (!memory.GetWritableSpan(a->address, a->size)) return false;\n    for (auto b = ranges.begin(); b != a; ++b)\n      if (b->address && u64{a->address} < u64{b->address} + b->size &&\n          u64{b->address} < u64{a->address} + a->size) return false;\n  }\n  return true;\n}\n} // namespace\n\nvoid DrvSetUserBindingCallback_entry(u32 callback) {\n  auto& state = kernel::GetCurrentState();\n  if (callback && !state.GetFunctionDispatcher()->GetFunction(callback)) {\n    REXKRNL_WARN(\"METRO_INPUT rejected unmapped binding callback {:08X}\", callback);\n    return;\n  }\n  state.hosted_pad_binding_callback.store(callback, std::memory_order_release);\n  REXKRNL_INFO(\"METRO_INPUT binding_callback={:08X}\", callback);\n}\n\nu32 XInputdGetCapabilities_entry(u32 context, u32 caps, u32 extra) {\n  auto& state = kernel::GetCurrentState();\n  auto user = HostedPadSlot(state, context);\n  if (!user) return kNotConnected;\n  auto& memory = state.GetGuestMemory();\n  if (!CheckOutputs(memory, {{caps, sizeof(rex::xam::X_INPUT_CAPABILITIES), true},\n                             {extra, 4, false}})) return X_STATUS_ACCESS_VIOLATION;\n  auto result = state.hosted_pad_input->GetCapabilities(*user);\n  if (!result) return kNotConnected;\n  const auto value = rex::xam::ToXInputCapabilities(*result);\n  if (!memory.Store(caps, value)) return X_STATUS_ACCESS_VIOLATION;\n  // The hosted provider has no auxiliary physical-controller condition to\n  // report. 17559 inspects this separate DWORD even on successful queries.\n  if (extra && !memory.Store(extra, be_u32{0})) return X_STATUS_ACCESS_VIOLATION;\n  return X_STATUS_SUCCESS;\n}\n\nu32 XInputdReadState_entry(u32 context, u32 packet, u32 gamepad, u32 extra) {\n  auto& state = kernel::GetCurrentState();\n  auto user = HostedPadSlot(state, context);\n  if (!user) return kNotConnected;\n  auto& memory = state.GetGuestMemory();\n  if (!CheckOutputs(memory, {{packet, 4, false},\n                             {gamepad, sizeof(rex::xam::X_INPUT_GAMEPAD), true},\n                             {extra, 4, false}})) return X_STATUS_ACCESS_VIOLATION;\n  auto reading = state.hosted_pad_input->GetState(*user);\n  if (!reading) return kNotConnected;\n  const auto value = rex::xam::ToXInputState(*reading);\n  if (!memory.Store(gamepad, value.gamepad) ||\n      (packet && !memory.Store(packet, value.packet_number)) ||\n      (extra && !memory.Store(extra, be_u32{0}))) return X_STATUS_ACCESS_VIOLATION;\n  const u16 buttons = static_cast<u16>(value.gamepad.buttons);\n  if (state.hosted_pad_buttons[*user].exchange(buttons, std::memory_order_relaxed) != buttons)\n    REXKRNL_INFO(\"METRO_GUEST_PAD context={:08X} user={} packet={} buttons=0x{:04X}\",\n                 context, *user, static_cast<u32>(value.packet_number), buttons);\n  return X_STATUS_SUCCESS;\n}\n"
RUNTIME="namespace rex::kernel {\nu32 TitleRuntime::AnnounceHostedPads() {\n  auto* thread = KernelThread::GetCallingThread();\n  if (!thread || &thread->GetRuntime() != this) return 0;\n  auto& state = StateOf(*this);\n  auto* input = state.hosted_pad_input;\n  auto* dispatcher = state.GetFunctionDispatcher();\n  const u32 callback = state.hosted_pad_binding_callback.load(std::memory_order_acquire);\n  if (!input || !dispatcher || !callback || !dispatcher->GetFunction(callback)) return 0;\n  auto& memory = GetGuestMemory();\n  u32 total = 0;\n  for (u32 user = 0; user < state.hosted_pad_state.size(); ++user) {\n    auto& slot = state.hosted_pad_state[user];\n    if (slot.load(std::memory_order_acquire) == 2) { ++total; continue; }\n    auto caps = input->GetCapabilities(user);\n    if (!caps || caps->subtype == 0) continue;\n    u8 previous = 0;\n    if (!slot.compare_exchange_strong(previous, 1, std::memory_order_acq_rel)) continue;\n    const auto port = memory.Allocate(4, 16, GuestProtect::kReadWrite, GuestHeap::kSystem);\n    if (!port) { slot.store(0); continue; }\n    if (!memory.Store(*port, u8{0xff})) {\n      (void)memory.Free(*port);\n      slot.store(0);\n      continue;\n    }\n    // The original binding callback owns port selection and guest bookkeeping.\n    // Contexts are stable opaque IDs for hosted pads, not guest pointers.\n    const u32 context = 0x10000001 + user;\n    u64 args[] = {context, context, 0, 0, *port};\n    const u64 status = dispatcher->Execute(thread->GetThreadState(), callback, args, 5);\n    const auto assigned = memory.Load<u8>(*port);\n    (void)memory.Free(*port);\n    if (status == 0 && assigned && *assigned < state.hosted_pad_state.size()) {\n      state.hosted_pad_port[user].store(*assigned, std::memory_order_release);\n      slot.store(2, std::memory_order_release);\n      ++total;\n      REXKRNL_INFO(\"METRO_INPUT bound context={:08X} host_user={} guest_port={}\",\n                    context, user, static_cast<u32>(*assigned));\n    } else {\n      state.hosted_pad_port[user].store(0xff);\n      slot.store(0, std::memory_order_release);\n      REXKRNL_WARN(\"METRO_INPUT bind failed context={:08X} result={:08X}\",\n                    context, static_cast<u32>(status));\n    }\n  }\n  return total;\n}\n} // namespace rex::kernel\n"
BODY += "\nu32 XInputdGetDeviceStats_entry(u32 context, [[maybe_unused]] u32 query,\n                                [[maybe_unused]] u32 output,\n                                [[maybe_unused]] u32 extra) {\n  auto& state = kernel::GetCurrentState();\n  auto user = HostedPadSlot(state, context);\n  if (!user) return kNotConnected;\n  // The hosted pad API exposes state, capabilities and identity, not the\n  // retail driver statistics structure. 17559 tests the sign of r3 and\n  // treats the old positive opaque context as success. Never publish\n  // success with an uninitialized or guessed output structure.\n  return X_STATUS_NOT_SUPPORTED;\n}\n"
BODY += "\nu32 XInputdReadTextKeystroke_entry(u32 port, u32 output) {\n  auto& state = kernel::GetCurrentState();\n  // The retail wrapper passes a user index and an eight-byte keystroke,\n  // not the opaque device context used by ReadState and GetCapabilities.\n  // Its status is Win32 ERROR_EMPTY (4306), not an NTSTATUS.\n  if (port >= state.hosted_pad_state.size() && port != rex::hid::IInputSystem::kAnyUser)\n    return X_ERROR_INVALID_PARAMETER;\n  auto& memory = state.GetGuestMemory();\n  if (!CheckOutputs(memory, {{output, sizeof(rex::xam::X_INPUT_KEYSTROKE), true}}))\n    return X_ERROR_INVALID_PARAMETER;\n  if (!state.hosted_pad_input) return X_ERROR_DEVICE_NOT_CONNECTED;\n  bool matched = false;\n  for (u32 host = 0; host < state.hosted_pad_state.size(); ++host) {\n    if (state.hosted_pad_state[host].load(std::memory_order_acquire) != 2) continue;\n    const u8 guest = state.hosted_pad_port[host].load(std::memory_order_acquire);\n    if (guest >= state.hosted_pad_state.size() ||\n        (port != rex::hid::IInputSystem::kAnyUser && guest != port)) continue;\n    matched = true;\n    auto key = state.hosted_pad_input->GetKeystroke(host, rex::hid::KeystrokeSource::kKeyboard);\n    if (!key) {\n      if (key.error().category != rex::ErrorCategory::kNotFound) return X_ERROR_FUNCTION_FAILED;\n      continue;\n    }\n    key->user = guest;\n    const auto value = rex::xam::ToXInputKeystroke(*key);\n    if (!memory.Store(output, value)) return X_ERROR_INVALID_PARAMETER;\n    return X_ERROR_SUCCESS;\n  }\n  return matched ? X_ERROR_EMPTY : X_ERROR_DEVICE_NOT_CONNECTED;\n}\n"
BODY += r"""
// XAM 816F29C0 uses a Win32 result and a QWORD interrupt-time output.
u32 XInputdGetLastTextInputTime_entry(u32 port, u32 output) {
  auto& state=kernel::GetCurrentState();
  auto& memory=state.GetGuestMemory();
  if(port>=state.hosted_pad_state.size() ||
     !CheckOutputs(memory,{{output,sizeof(be_u64),true}}))
    return X_ERROR_INVALID_PARAMETER;
  if(!state.hosted_pad_input)return X_ERROR_DEVICE_NOT_CONNECTED;
  for(u32 host=0;host<state.hosted_pad_state.size();++host) {
    if(state.hosted_pad_state[host].load(std::memory_order_acquire)!=2 ||
       state.hosted_pad_port[host].load(std::memory_order_acquire)!=port)continue;
    const auto time=state.hosted_pad_input->GetLastTextActivity100ns(host);
    if(!time)return X_ERROR_DEVICE_NOT_CONNECTED;
    return memory.Store(output,be_u64{*time})?X_ERROR_SUCCESS:X_ERROR_INVALID_PARAMETER;
  }
  return X_ERROR_DEVICE_NOT_CONNECTED;
}
"""
# Original 17559 Guide callback proof: metro_guide_evidence.py.
# Registration uses only r3 (mapped callback or zero). The original callback
# receives (device context, subdevice index, system request type). The
# ordinary Guide press is request zero, independently verified at 816F3E14
# and the original XamInputSendXenonButtonPress wrapper.
FIELDS += r"""
  std::atomic<u64> hosted_sysreq_registration{0};
  std::array<std::atomic<u64>, rex::hid::IInputSystem::kMaxUsers> hosted_sysreq_samples{};
  std::atomic<u32> hosted_sysreq_delivered{0};
"""
# Install reset in the existing per-title lifetime hook.
FIELDS=FIELDS.replace("    hosted_pad_binding_callback.store(0);",
    "    hosted_pad_binding_callback.store(0);\n"
    "    hosted_sysreq_registration.fetch_add(1ull<<32);\n"
    "    hosted_sysreq_registration.fetch_and(0xffffffff00000000ull);\n"
    "    for (auto& sample : hosted_sysreq_samples) sample.store(0);\n"
    "    hosted_sysreq_delivered.store(0);")
BODY += r"""
void DrvSetSysReqCallback_entry(u32 callback) {
  auto& state=kernel::GetCurrentState();
  if (callback && !state.GetFunctionDispatcher()->GetFunction(callback)) {
    REXKRNL_WARN("METRO_SYSREQ rejected unmapped callback={:08X}",callback);
    return;
  }
  auto& registration=state.hosted_sysreq_registration;
  u64 before=registration.load(std::memory_order_acquire);
  for (;;) {
    const u64 after=((before+(1ull<<32))&0xffffffff00000000ull)|callback;
    if (registration.compare_exchange_weak(before,after,std::memory_order_acq_rel))
      break;
  }
  REXKRNL_INFO("METRO_SYSREQ registration callback={:08X}",callback);
}

namespace {
// A complete sample consists of packet serial number and actual Guide bit.
// Concurrent guest reads of the same controller must not generate duplicate
// requests or replay an older sample. Signed serial comparison handles wrap.
bool HostedGuideRisingEdge(std::atomic<u64>& sample,u32 packet,bool pressed) {
  constexpr u64 valid=1ull<<63;
  const u64 next=valid|(u64{packet}<<1)|(pressed?1ull:0ull);
  u64 previous=sample.load(std::memory_order_acquire);
  for (;;) {
    if ((previous&valid) &&
        static_cast<i32>(packet-static_cast<u32>(previous>>1))<=0)
      return false;
    if (sample.compare_exchange_weak(previous,next,std::memory_order_acq_rel))
      return pressed && !(previous&1);
  }
}

void DispatchHostedGuide(u32 user,u32 context,u32 packet,u16 buttons) {
  auto& runtime=kernel::GetCurrent();
  auto& state=kernel::GetCurrentState();
  if (user>=state.hosted_pad_state.size() ||
      state.hosted_pad_state[user].load(std::memory_order_acquire)!=2)
    return;
  if (!HostedGuideRisingEdge(state.hosted_sysreq_samples[user],packet,(buttons&0x0400)!=0))
    return;
  const u64 registration=state.hosted_sysreq_registration.load(std::memory_order_acquire);
  const u32 callback=static_cast<u32>(registration);
  if (!callback) {
    REXKRNL_INFO("METRO_SYSREQ Guide edge has no registered original callback");
    return;
  }
  const u32 system_process=state.GetSystemProcess();
  if (!system_process || state.IsTerminatingTitle())return;
  // Never re-enter the original driver's callback on the polling guest
  // thread. XAM may hold locks while it reads input. A distinct system
  // guest thread performs the exact original callback, outside host locks.
  auto worker=std::make_unique<KernelThread>(runtime,0,0,
    [&runtime,user,context,registration,callback,system_process]() -> int {
      auto& current=StateOf(runtime);
      if (current.hosted_sysreq_registration.load(std::memory_order_acquire)!=registration ||
          current.hosted_pad_state[user].load(std::memory_order_acquire)!=2 ||
          current.IsTerminatingTitle())return 0;
      auto* thread=KernelThread::GetCallingThread();
      auto* body=thread?thread->GetGuestObject<X_KTHREAD>():nullptr;
      if (!body || static_cast<u32>(body->process)!=system_process ||
          body->process_type!=kXProcTypeSystem)return 1;
      auto* dispatcher=current.GetFunctionDispatcher();
      if (!dispatcher || !dispatcher->GetFunction(callback))return 1;
      u64 args[]={context,0,0};
      REXKRNL_INFO("METRO_SYSREQ deliver callback={:08X} context={:08X} subdevice=0 request=0",
                   callback,context);
      dispatcher->Execute(thread->GetThreadState(),callback,args,3);
      current.hosted_sysreq_delivered.fetch_add(1,std::memory_order_relaxed);
      REXKRNL_INFO("METRO_SYSREQ callback_return");
      return 0;
    },system_process,true);
  auto launched=runtime.GetThreadRegistry().Launch(std::move(worker));
  if (!launched) {
    REXKRNL_WARN("METRO_SYSREQ unable to schedule original callback");
    return;
  }
  CloseOwned(runtime.GetObjectTable(),*launched);
}
} // namespace
"""
# Forward declaration must precede XInputdReadState. Keep the original
# gamepad state unchanged; system requests are a separate driver signal.
BODY=BODY.replace("u32 XInputdReadState_entry(",
    "namespace { void DispatchHostedGuide(u32 user,u32 context,u32 packet,u16 buttons); }\n\n"
    "u32 XInputdReadState_entry(",1)
needle="                 context, *user, static_cast<u32>(value.packet_number), buttons);\n  return X_STATUS_SUCCESS;"
BODY=replace(BODY,needle,needle.replace("  return X_STATUS_SUCCESS;",
    "  DispatchHostedGuide(*user,context,static_cast<u32>(value.packet_number),buttons);\n  return X_STATUS_SUCCESS;"))

EXPORTS=("DrvSetSysReqCallback","DrvSetUserBindingCallback","XInputdGetCapabilities","XInputdReadState","XInputdGetDeviceStats","XInputdReadTextKeystroke","XInputdGetLastTextInputTime")

HID_CLOCK_OLD="""/**
 * Writes 0 as the time of the last HID input.
 *
 * @param time_ptr Receives the time.
 * @return X_STATUS_SUCCESS.
 */
u32 HidGetLastInputTime_entry(MappedU32 time_ptr) {
  if (time_ptr) {
    *time_ptr = 0;
  }
  return X_STATUS_SUCCESS;
}"""
HID_CLOCK_NEW="""// Original XAM 816F29F4 loads all eight bytes written by this API.
u32 HidGetLastInputTime_entry(u32 output) {
  auto& state=kernel::GetCurrentState();
  auto& memory=state.GetGuestMemory();
  if(!output || !memory.GetWritableSpan(output,sizeof(be_u64)))
    return X_STATUS_ACCESS_VIOLATION;
  if(!state.hosted_pad_input)return X_STATUS_NOT_SUPPORTED;
  const auto time=state.hosted_pad_input->GetLastHidActivity100ns();
  if(!time)return X_STATUS_NOT_SUPPORTED;
  return memory.Store(output,be_u64{*time})?X_STATUS_SUCCESS:X_STATUS_ACCESS_VIOLATION;
}"""

def patch_activity_clock(public,private,source):
    anchor="  [[nodiscard]] virtual std::string InputSourceToString(const InputSource& source) const = 0;"
    public=replace(public,anchor,anchor+"""
  // Native hosted input timestamps, in the guest interrupt clock domain.
  // Providers without this capability must not claim a populated timestamp.
  [[nodiscard]] virtual Result<u64> GetLastHidActivity100ns() const {
    return std::unexpected(Error(ErrorCategory::kNotFound,"HID activity unavailable"));
  }
  [[nodiscard]] virtual Result<u64> GetLastTextActivity100ns(u32) {
    return std::unexpected(Error(ErrorCategory::kNotFound,"text activity unavailable"));
  }
""")
    anchor="  [[nodiscard]] std::string InputSourceToString(const InputSource& source) const override;"
    private=replace(private,anchor,anchor+"""
  [[nodiscard]] Result<u64> GetLastHidActivity100ns() const override;
  [[nodiscard]] Result<u64> GetLastTextActivity100ns(u32 user) override;
""")
    source=replace(source,"  std::atomic<i32> ui_blocks{0};","""  std::atomic<i32> ui_blocks{0};
  std::atomic<u64> last_hid_activity{0};
  std::atomic<u64> last_text_activity{0};""")
    source=replace(source,"  state.started = true;","""  state.last_hid_activity.store(0,std::memory_order_relaxed);
  state.last_text_activity.store(0,std::memory_order_relaxed);
  state.started = true;""")
    source=replace(source,"  state.started = false;","""  state.started = false;
  state.last_hid_activity.store(0,std::memory_order_relaxed);
  state.last_text_activity.store(0,std::memory_order_relaxed);""")
    source=replace(source,"  state.keyboard_mouse->OnEvent(forwarded);","""  // The original idle code compares both results with KeQueryInterruptTime.
  // Count actual captured window input, not focus/resize or synthetic polling.
  const bool key=event.type==Type::kKeyDown || event.type==Type::kKeyChar;
  const bool mouse=event.type==Type::kButtonDown ||
       (event.type==Type::kMotion && (forwarded.dx!=0 || forwarded.dy!=0)) ||
       (event.type==Type::kWheel && event.scroll_y!=0);
  if(state.IsActive() && state.ui_blocks.load(std::memory_order_relaxed)==0 && (key || mouse)) {
    const u64 ticks=Clock::QueryGuestTickCount(),frequency=Clock::GetGuestTickFrequency();
    if(frequency) {
      const u64 time=ticks/frequency*10000000 + ticks%frequency*10000000/frequency;
      state.last_hid_activity.store(time,std::memory_order_release);
      if(key && settings_.mnk_passthrough.Get())
        state.last_text_activity.store(time,std::memory_order_release);
    }
  }
  state.keyboard_mouse->OnEvent(forwarded);""")
    source=replace(source,"void InputSystem::SetInputCaptured(bool captured) {","""Result<u64> InputSystem::GetLastHidActivity100ns() const {
  State& state=*state_;
  std::lock_guard lock(state.mutex);
  if(!state.started)return std::unexpected(NotFound("input not started"));
  return state.last_hid_activity.load(std::memory_order_acquire);
}
Result<u64> InputSystem::GetLastTextActivity100ns(u32 user) {
  State& state=*state_;
  std::vector<ConnectionEvent> events;
  Result<u64> result=std::unexpected(NotFound("input not started or invalid user"));
  {
    std::lock_guard lock(state.mutex);
    if(state.started && user<detail::kMaxUsers) {
      state.RefreshDevicesLocked(events);
      const bool keyboard=std::ranges::any_of(state.users[user],[&](const detail::DeviceKey& key) {
        return key.source==state.keyboard_mouse_source;
      });
      result=keyboard?state.last_text_activity.load(std::memory_order_acquire):u64{0};
    }
  }
  state.Fire(events);
  return result;
}
void InputSystem::SetInputCaptured(bool captured) {""")
    return public,private,source


def patch_input_fixture(header,source):
    header=replace(header,"namespace apu {\nclass IAudioSystem;","namespace hid {\nclass IInputSystem;\n}\nnamespace apu {\nclass IAudioSystem;")
    header=replace(header,"std::string ui_driver = {});","std::string ui_driver = {}, std::string input_driver = {});")
    header=replace(header,"  rex::apu::IAudioSystem& GetAudio();","  rex::apu::IAudioSystem& GetAudio();\n  rex::hid::IInputSystem& GetInput();")
    source=replace(source,"#include <rex/apu/audio_system.h>","#include <rex/apu/audio_system.h>\n#include <rex/hid/input_system.h>")
    source=replace(source,"std::vector<IModule*> providers, std::string audio_driver, std::string ui_driver)\n      : ObjectApp","std::vector<IModule*> providers, std::string audio_driver, std::string ui_driver, std::string input_driver)\n      : ObjectApp")
    source=replace(source,"ui_driver_(std::move(ui_driver)) {}","ui_driver_(std::move(ui_driver)), input_driver_(std::move(input_driver)) {}")
    source=replace(source,"    if (!audio_driver_.empty()) {","    if (!input_driver_.empty()) {\n      REX_TRY_VOID(GetInput().GetSettings().drivers.SetText(SettingLayer::kTitle, input_driver_));\n    }\n    if (!audio_driver_.empty()) {")
    source=replace(source,"  std::string ui_driver_;","  std::string ui_driver_;\n  std::string input_driver_;")
    source=replace(source,"std::vector<IModule*> providers, std::string audio_driver, std::string ui_driver)\n      : app","std::vector<IModule*> providers, std::string audio_driver, std::string ui_driver, std::string input_driver)\n      : app")
    source=replace(source,"std::move(ui_driver)),\n        tool","std::move(ui_driver), std::move(input_driver)),\n        tool")
    source=replace(source,"std::string ui_driver)\n    : impl_","std::string ui_driver, std::string input_driver)\n    : impl_")
    source=replace(source,"std::move(ui_driver))) {","std::move(ui_driver), std::move(input_driver))) {")
    source=replace(source,"rex::ui::IUISystem& KernelFixture::GetUI() {","rex::hid::IInputSystem& KernelFixture::GetInput() {\n  return impl_->app.GetInput();\n}\n\nrex::ui::IUISystem& KernelFixture::GetUI() {")
    return header,source

def patch_sources(sdk,tests):
    h=sdk/"src/kernel/title_state.h"
    cpp=sdk/"src/kernel/title_state.cpp"
    public=sdk/"include/rex/kernel/title_runtime.h"
    hid=sdk/"src/kernel/xboxkrnl/xboxkrnl_hid.cpp"
    test=sdk/"tests/unit/kernel/xam_input_test.cpp"
    outputs={}
    fixture_h=sdk/"tests/unit/kernel/kernel_fixture.h"
    fixture_cpp=sdk/"tests/unit/kernel/kernel_fixture.cpp"
    outputs[fixture_h],outputs[fixture_cpp]=patch_input_fixture(fixture_h.read_text(),fixture_cpp.read_text())
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
    source=replace(source,old,old+"\n#include <rex/kernel/guest_memory.h>\n#include <rex/kernel/function_dispatcher.h>\n#include <rex/kernel/object/kernel_thread.h>\n#include <rex/kernel/thread_registry.h>\n#include <rex/kernel/object/object_table.h>\n#include <rex/kernel/types/thread.h>\n#include <initializer_list>\n#include <optional>\n#include \"kernel/title_state.h\"\n#include \"kernel/kernel.h\"\n#include \"kernel/categories.h\"\n#include \"xam/input_convert.h\"")
    old="}  // namespace rex::kernel::xboxkrnl"
    source=replace(source,old,BODY+"\n"+old+"\n\n"+RUNTIME)
    for name in EXPORTS:
        source=replace(source,"REX_EXPORT_STUB(__imp__"+name+");",
                       "REX_EXPORT(__imp__"+name+", rex::kernel::xboxkrnl::"+name+"_entry)")
    outputs[hid]=replace(source,HID_CLOCK_OLD,HID_CLOCK_NEW)
    input_public=sdk/"include/rex/hid/input_system.h"
    input_private=sdk/"src/hid/input_system.h"
    input_source=sdk/"src/hid/input_system.cpp"
    outputs[input_public],outputs[input_private],outputs[input_source]=patch_activity_clock(
        input_public.read_text(),input_private.read_text(),input_source.read_text())
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
