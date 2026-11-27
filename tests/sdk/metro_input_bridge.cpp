
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
