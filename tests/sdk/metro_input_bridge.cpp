
// Use the actual guest-thread export wrapper and the SDK's input provider.
// Tool-mode fixtures load without attaching systems, so explicitly connect the
// fixture's app provider using the same per-title state field AttachSystems sets.
#include "kernel_fixture.h"
#include "kernel/title_state.h"
#include <rex/kernel/function_dispatcher.h>
#include <rex/kernel/title_runtime.h>
#include <rex/kernel/guest_memory.h>
#include <rex/kernel/types/status.h>

REX_TEST_CASE("metro_input_bridge: unmapped callbacks and unannounced contexts are rejected",
              "[kernel][input][metro_input_bridge]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    auto& state=StateOf(c.GetRuntime());
    const u32 data=c.Alloc(16), packet=c.Alloc(4), extra=c.Alloc(4);
    c.Store32(data,0xdeadbeef);
    c.Kernel("DrvSetUserBindingCallback",{0xdeadbeec});
    CHECK(state.hosted_pad_binding_callback.load()==0);
    CHECK(c.GetRuntime().AnnounceHostedPads()==0);
    CHECK(c.Kernel("XInputdReadState",{0x10000001,packet,data,extra})==0xc000009d);
    CHECK(c.Load32(data)==0xdeadbeef);
    const u32 callback=state.GetFunctionDispatcher()->AllocateThunk(
      +[](PPCContext& ctx,u8*) {ctx.r3.u64=0;},0);
    REQUIRE(callback!=0);
    c.Kernel("DrvSetUserBindingCallback",{callback});
    CHECK(state.hosted_pad_binding_callback.load()==callback);
    c.Kernel("DrvSetUserBindingCallback",{0});
    CHECK(state.hosted_pad_binding_callback.load()==0);
  });
}

REX_TEST_CASE("metro_input_bridge: statistics failure cannot masquerade as populated output",
              "[kernel][input][metro_input_bridge]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    const u32 data=c.Alloc(32), extra=c.Alloc(16);
    for (u32 offset=0;offset<32;offset+=4) c.Store32(data+offset,0xdeadbeef);
    for (u32 offset=0;offset<16;offset+=4) c.Store32(extra+offset,0xcafebabe);
    const u32 status=c.Kernel("XInputdGetDeviceStats",{0x10000001,1,data,extra});
    CHECK(status==0xc000009d);
    CHECK((status&0x80000000u)!=0);
    CHECK(c.Kernel("XInputdGetDeviceStats",{0,1,0,0})==0xc000009d);
    for (u32 offset=0;offset<32;offset+=4) CHECK(c.Load32(data+offset)==0xdeadbeef);
    for (u32 offset=0;offset<16;offset+=4) CHECK(c.Load32(extra+offset)==0xcafebabe);
  });
}

REX_TEST_CASE("metro_input_bridge: connected provider, original callback ABI and guest reads",
              "[kernel][input][metro_input_bridge]") {
  using namespace rex::test_input;
  g_fake = {};
  FakeProvider provider;
  g_fake[0].devices = {MakePad(1, 0), MakePad(2, 1)};
  g_fake[0].states[1] = Buttons(rex::hid::kPadDPadRight);
  g_fake[0].states[2] = Buttons(rex::hid::kPadA);
  rex::test::KernelFixture fixture({}, {&provider}, {}, {}, "fake_a");
  auto& input = fixture.GetInput();
  input.SetInputCaptured(true);
  auto& title = StateOf(fixture.GetRuntime());
  title.hosted_pad_input = &input;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    auto& runtime=c.GetRuntime();
    auto& state=StateOf(runtime);
    const u32 callback=state.GetFunctionDispatcher()->AllocateThunk(
      +[](PPCContext& ctx,u8* base) {
        if (ctx.r3.u32 != ctx.r4.u32 || ctx.r5.u32 || ctx.r6.u32 ||
            ctx.r3.u32<0x10000001 || ctx.r3.u32>0x10000002 || !ctx.r7.u32) {
          ctx.r3.u64=0xc000000d; return;
        }
        base[ctx.r7.u32]=static_cast<u8>(ctx.r3.u32-0x10000001);
        ctx.r3.u64=0;
      },0);
    REQUIRE(callback);
    c.Kernel("DrvSetUserBindingCallback",{callback});
    REQUIRE(runtime.AnnounceHostedPads()==2);
    CHECK(runtime.AnnounceHostedPads()==2);
    CHECK(state.hosted_pad_port[0].load()==0);
    CHECK(state.hosted_pad_port[1].load()==1);
    const u32 data=c.Alloc(12), packet=c.Alloc(4), extra=c.Alloc(4), caps=c.Alloc(20);
    REQUIRE(c.Kernel("XInputdGetCapabilities",{0x10000001,caps,extra})==0);
    CHECK(c.Load8(caps)==1);
    CHECK(c.Load8(caps+1)==1);
    CHECK(c.Load32(extra)==0);
    REQUIRE(c.Kernel("XInputdReadState",{0x10000001,packet,data,extra})==0);
    CHECK(c.Load32(data)==0x00080000);
    const u32 previous=c.Load32(packet);
    REQUIRE(c.Kernel("XInputdReadState",{0x10000001,packet,data,extra})==0);
    CHECK(c.Load32(packet)==previous);
    REQUIRE(c.Kernel("XInputdReadState",{0x10000002,0,data,0})==0);
    CHECK(c.Load32(data)==0x10000000);
    c.Store32(data,0xdeadbeef);
    CHECK(c.Kernel("XInputdReadState",{0x10000001,data,data,extra})==rex::kernel::X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Load32(data)==0xdeadbeef);
    CHECK(c.Kernel("XInputdGetCapabilities",{0x10000001,caps,caps+4})==rex::kernel::X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("XInputdReadState",{0x10000001,packet,0xfffffffc,extra})==rex::kernel::X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("XInputdGetDeviceStats",{0x10000001,1,data,extra})==rex::kernel::X_STATUS_NOT_SUPPORTED);
    CHECK(c.Load32(data)==0xdeadbeef);
    const u32 key=c.Alloc(8);
    c.Store64(key,0xdeadbeefcafebabeull);
    CHECK(c.Kernel("XInputdReadTextKeystroke",{0,key})==rex::kernel::X_ERROR_EMPTY);
    CHECK(c.Kernel("XInputdReadTextKeystroke",{1,key})==rex::kernel::X_ERROR_EMPTY);
    CHECK(c.Kernel("XInputdReadTextKeystroke",{3,key})==rex::kernel::X_ERROR_DEVICE_NOT_CONNECTED);
    CHECK(c.Kernel("XInputdReadTextKeystroke",{9,key})==rex::kernel::X_ERROR_INVALID_PARAMETER);
    CHECK(c.Kernel("XInputdReadTextKeystroke",{0,0xfffffffc})==rex::kernel::X_ERROR_INVALID_PARAMETER);
    CHECK(c.Load32(key)==0xdeadbeef);
    CHECK(c.Load32(key+4)==0xcafebabe);
    CHECK(c.Kernel("XInputdReadState",{0x10000003,packet,data,extra})==0xc000009d);
    g_fake[0].states[1] = Buttons(rex::hid::kPadDPadLeft);
    REQUIRE(c.Kernel("XInputdReadState",{0x10000001,packet,data,extra})==0);
    CHECK(c.Load32(data)==0x00040000);
    CHECK(c.Load32(packet)!=previous);
    g_fake[0].states[1] = Buttons(0);
    REQUIRE(c.Kernel("XInputdReadState",{0x10000001,packet,data,extra})==0);
    CHECK(c.Load32(data)==0);
    state.ResetHostedPadBindings();
    CHECK(runtime.AnnounceHostedPads()==0);
    CHECK(c.Kernel("XInputdReadState",{0x10000001,packet,data,extra})==0xc000009d);
  });
}

REX_TEST_CASE("metro_input_bridge: host text events preserve queue on bad guest output",
              "[kernel][input][metro_input_bridge]") {
  using namespace rex::test_input;
  g_fake = {};
  FakeProvider provider;
  g_fake[0].devices={MakePad(1,0)};
  g_fake[0].states[1]=Buttons(0);
  rex::test::KernelFixture fixture({}, {&provider}, {}, {}, "fake_a");
  auto& input=fixture.GetInput();
  REQUIRE(input.GetSettings().mnk_passthrough.Set(true));
  input.SetInputCaptured(true);
  StateOf(fixture.GetRuntime()).hosted_pad_input=&input;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    auto& state=StateOf(c.GetRuntime());
    const u32 callback=state.GetFunctionDispatcher()->AllocateThunk(
      +[](PPCContext& ctx,u8* base) {base[ctx.r7.u32]=0; ctx.r3.u64=0;},0);
    REQUIRE(callback);
    c.Kernel("DrvSetUserBindingCallback",{callback});
    REQUIRE(c.GetRuntime().AnnounceHostedPads()==1);
    rex::InputEvent event{.type=rex::InputEvent::Type::kKeyDown,.key=rex::VirtualKey::kW};
    state.hosted_pad_input->OnInputEvent(event);
    const u32 out=c.Alloc(8);
    CHECK(c.Kernel("XInputdReadTextKeystroke",{0,0xfffffffc})==rex::kernel::X_ERROR_INVALID_PARAMETER);
    REQUIRE(c.Kernel("XInputdReadTextKeystroke",{0,out})==0);
    CHECK((c.Load32(out)>>16)!=0);
    CHECK(c.Load8(out+6)==0);
    CHECK((c.Load32(out+4)>>16 & 1)!=0);
    CHECK(c.Kernel("XInputdReadTextKeystroke",{0,out})==rex::kernel::X_ERROR_EMPTY);
    state.ResetHostedPadBindings();
  });
}
