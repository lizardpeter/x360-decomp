
#include "kernel_fixture.h"
#include "kernel/title_state.h"
#include <rex/kernel/function_dispatcher.h>
#include <rex/kernel/object/kernel_thread.h>
#include <rex/kernel/title_runtime.h>
#include <rex/kernel/guest_memory.h>
#include <rex/kernel/types/status.h>
#include <rex/platform/file.h>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <tuple>
#include <rex/kernel/module.h>

namespace {
std::atomic<u32> metro_gfx_calls{0},metro_gfx_event{0},metro_gfx_pointer{0};
std::atomic<u32> metro_gfx_thread{0},metro_gfx_first{0},metro_gfx_last{0};
void MetroGraphicsProbe(PPCContext& ctx,u8* base) {
  metro_gfx_event=ctx.r4.u32;
  metro_gfx_pointer=ctx.r5.u32;
  auto* thread=rex::kernel::KernelThread::GetCallingThread();
  metro_gfx_thread=thread?thread->GetThreadState()->GetThreadID():0;
  metro_gfx_first=base[ctx.r5.u32];
  metro_gfx_last=base[ctx.r5.u32+(ctx.r4.u32==1?63:7)];
  metro_gfx_calls.fetch_add(1);
}
}

REX_TEST_CASE("metro_graphics_notification: original registration and synchronous 64/8 byte ABI",
              "[kernel][metro_graphics_notification]") {
  using namespace rex::kernel;
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    auto& state=StateOf(c.GetRuntime());
    auto* dispatcher=state.GetFunctionDispatcher();
    const u32 callback=0x816CBFD8;
    REQUIRE(dispatcher->InitializeFunctionTable(0x816C0000,0x10000,0x816C0000,0x10000));
    REQUIRE(dispatcher->SetFunction(callback,&MetroGraphicsProbe));
    metro_gfx_calls=0;
    const u32 payload=c.Alloc(64);
    c.Store32(payload,0xab000000);
    c.Store32(payload+4,0x000000ef);
    c.Store32(payload+60,0x000000cd);
    // A mapped but non-retail registration must not acquire this private
    // system callback contract. The fixture explicitly selects the test scope.
    c.Kernel("VdRegisterXamGraphicsNotification",{callback});
    CHECK(state.metro_xam_graphics_callback.load()==0);
    state.retail_xam_hmodule=1;
    struct Reset { decltype(state)& value; ~Reset(){value.retail_xam_hmodule=0;value.metro_xam_graphics_callback.store(0);} } reset{state};
    c.Kernel("VdRegisterXamGraphicsNotification",{0xdeadbeec});
    CHECK(state.metro_xam_graphics_callback.load()==0);
    c.Kernel("VdRegisterXamGraphicsNotification",{callback});
    REQUIRE(state.metro_xam_graphics_callback.load()==callback);
    REQUIRE(c.Kernel("VdCallGraphicsNotificationRoutines",{1,payload})==X_STATUS_SUCCESS);
    CHECK(metro_gfx_calls.load()==1);
    CHECK(metro_gfx_event.load()==1);
    CHECK(metro_gfx_pointer.load()==payload);
    CHECK(metro_gfx_first.load()==0xab);
    CHECK(metro_gfx_last.load()==0xcd);
    CHECK(metro_gfx_thread.load()==KernelThread::GetCallingThread()->GetThreadState()->GetThreadID());
    REQUIRE(c.Kernel("VdCallGraphicsNotificationRoutines",{9,payload})==X_STATUS_SUCCESS);
    CHECK(metro_gfx_calls.load()==2);
    CHECK(metro_gfx_event.load()==9);
    CHECK(metro_gfx_last.load()==0xef);
    CHECK(c.Kernel("VdCallGraphicsNotificationRoutines",{9,0})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("VdCallGraphicsNotificationRoutines",{1,0xfffffff0})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("VdCallGraphicsNotificationRoutines",{10,payload})==X_STATUS_NOT_SUPPORTED);
    CHECK(metro_gfx_calls.load()==2);
    c.Kernel("VdRegisterXamGraphicsNotification",{0});
    CHECK(state.metro_xam_graphics_callback.load()==0);
    CHECK(c.Kernel("VdCallGraphicsNotificationRoutines",{1,payload})==X_STATUS_SUCCESS);
    CHECK(metro_gfx_calls.load()==2);
  });
}

REX_TEST_CASE("metro_graphics_notification: genuine original HUD resource XEX maps byte for byte",
              "[kernel][metro_graphics_notification][metro_hud_skin]") {
  using namespace rex::kernel;
  const char* root=std::getenv("METRO_ORIGINAL_HUD_SKIN_FIXTURES");
  REQUIRE(root);
  const std::filesystem::path source(root);
  const auto decoded=rex::platform::ReadHostFile(source/"huduiskin.decoded");
  REQUIRE(decoded);
  REQUIRE(decoded->size()==233472);
  rex::test::KernelFixture fixture([&](const std::filesystem::path& dir) {
    std::filesystem::copy_file(source/"huduiskin.xex",dir/"huduiskin.xex");
  });
  fixture.RunOnGuestThread([&](rex::test::Caller& c) {
    const auto path=c.AllocString("game:\\huduiskin.xex");
    const u32 out=c.Alloc(4),data=c.Alloc(4),size=c.Alloc(4);
    REQUIRE(c.Kernel("XexLoadImage",{path,0x40000008,0,out})==X_STATUS_SUCCESS);
    const u32 handle=c.Load32(out);
    REQUIRE(handle);
    auto& memory=c.GetRuntime().GetGuestMemory();
    const auto span=memory.GetReadOnlySpan(0x90F90000,233472);
    REQUIRE(span);
    REQUIRE(std::memcmp(span->data(),decoded->data(),decoded->size())==0);
    CHECK_FALSE(c.GetRuntime().FindFunction(0x90F90000));
    for (const auto& item : {std::tuple<const char*,u32,u32>{"skin",0x90F90000,75851},
                            {"xam",0x90FA2880,156069}}) {
      REQUIRE(c.Kernel("XexGetModuleSection",{handle,c.AllocString(std::get<0>(item)),data,size})==X_STATUS_SUCCESS);
      CHECK(c.Load32(data)==std::get<1>(item));
      CHECK(c.Load32(size)==std::get<2>(item));
      CHECK(c.Load32(c.Load32(data))==0x5855495a);
    }
    REQUIRE(c.Kernel("XexUnloadImage",{handle})==X_STATUS_SUCCESS);
    CHECK_FALSE(c.GetRuntime().GetModuleRegistry().FindUserModule("huduiskin.xex"));
  });
}
