
#include "kernel_fixture.h"
#include "kernel/title_state.h"
#include <rex/kernel/function_dispatcher.h>
#include <rex/kernel/object/kernel_thread.h>
#include <rex/kernel/types/thread.h>
#include <rex/kernel/title_runtime.h>

REX_TEST_CASE("metro_system_attach: DLL entry receives real system process and isolated TLS",
              "[kernel][metro_system_attach]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    auto& runtime=c.GetRuntime();
    auto& state=StateOf(runtime);
    auto* caller=rex::kernel::KernelThread::GetCallingThread();
    const u32 caller_process=caller->GetGuestObject<rex::kernel::X_KTHREAD>()->process;
    REQUIRE(caller_process==state.GetTitleProcess());
    REQUIRE(c.Kernel("KeGetCurrentProcessType")==rex::kernel::kXProcTypeUser);
    const u32 slot=c.Kernel("KeTlsAlloc");
    REQUIRE(slot!=0xffffffff);
    REQUIRE(c.Kernel("KeTlsSetValue",{slot,0x12345678})!=0);
    const u32 output=c.Alloc(16);
    const u32 callback=state.GetFunctionDispatcher()->AllocateThunk(
      +[](PPCContext& ctx,u8* base) {
        auto* current=rex::kernel::KernelThread::GetCallingThread();
        auto& runtime=current->GetRuntime();
        rex::test::Caller worker(ctx,base,runtime);
        const u32 out=ctx.r3.u32;
        if (ctx.r4.u32!=1 || ctx.r5.u32!=0) {ctx.r3.u64=0; return;}
        worker.Store32(out,worker.Kernel("KeGetCurrentProcessType"));
        worker.Store32(out+4,current->GetGuestObject<rex::kernel::X_KTHREAD>()->process);
        const u32 tls=worker.Kernel("KeTlsAlloc");
        worker.Store32(out+8,tls);
        if (tls!=0xffffffff) {
          worker.Store32(out+12,worker.Kernel("KeTlsGetValue",{tls}));
          worker.Kernel("KeTlsFree",{tls});
        }
        ctx.r3.u64=0x1234;
      },0);
    REQUIRE(callback);
    auto result=runtime.AttachHostedSystemModule(callback,output);
    REQUIRE(result);
    CHECK(result->entry_result==0x1234);
    CHECK(result->bound_pads==0);
    CHECK(c.Load32(output)==rex::kernel::kXProcTypeSystem);
    CHECK(c.Load32(output+4)==state.GetSystemProcess());
    CHECK(c.Load32(output+4)!=caller_process);
    CHECK(c.Load32(output+8)!=0xffffffff);
    CHECK(c.Load32(output+12)==0);
    CHECK(c.Kernel("KeGetCurrentProcessType")==rex::kernel::kXProcTypeUser);
    CHECK(c.Kernel("KeTlsGetValue",{slot})==0x12345678);
    CHECK_FALSE(runtime.AttachHostedSystemModule(0xdeadbeec,output));
    CHECK_FALSE(runtime.AttachHostedSystemModule(callback,0));
    c.Kernel("KeTlsFree",{slot});
  });
}

REX_TEST_CASE("metro_system_attach: actual zero return remains a failed DLL attach",
              "[kernel][metro_system_attach]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    auto& runtime=c.GetRuntime();
    auto* dispatcher=StateOf(runtime).GetFunctionDispatcher();
    const u32 callback=dispatcher->AllocateThunk(
      +[](PPCContext& ctx,u8*) {ctx.r3.u64=0;},0);
    REQUIRE(callback);
    auto result=runtime.AttachHostedSystemModule(callback,1);
    REQUIRE(result);
    CHECK(result->entry_result==0);
    CHECK(result->bound_pads==0);
  });
}
