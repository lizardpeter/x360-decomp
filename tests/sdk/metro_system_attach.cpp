
#include "kernel_fixture.h"
#include "kernel/title_state.h"
#include <rex/kernel/function_dispatcher.h>
#include <rex/kernel/object/kernel_thread.h>
#include <rex/kernel/types/thread.h>
#include <rex/kernel/heap.h>
#include <rex/kernel/title_runtime.h>

REX_TEST_CASE("metro_system_attach: DLL entry receives real system process and isolated TLS",
              "[kernel][metro_system_attach]") {
  rex::test::KernelFixture fixture;
  // A tool-mode title has no TLS header. Configure a real title TLS slot
  // layout before creating the test caller, just like the SDK TLS suite.
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    auto& state=StateOf(c.GetRuntime());
    auto* process=state.GetAddressSpace()->TranslateVirtual<rex::kernel::X_KPROCESS*>(state.GetTitleProcess());
    process->tls_slot_size=128;
    process->tls_slot_bitmap[0]=0xffffffffu;
  });
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
    CHECK(c.Load32(output+8)==slot);
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

#include <rex/kernel/object/object_table.h>
#include <rex/kernel/thread_registry.h>
#include <chrono>
#include <thread>

REX_TEST_CASE("metro_system_attach: pointer-returning system thread owns a reference not a hidden handle",
              "[kernel][metro_system_attach]") {
  using namespace rex::kernel;
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    auto& table=c.GetRuntime().GetObjectTable();
    const u32 out=c.Alloc(4), id=c.Alloc(4), seen=c.Alloc(8), handle_out=c.Alloc(4);
    const u32 context=rex::test::Caller::RegisterBody([seen](rex::test::Caller& worker) {
      worker.Store32(seen,worker.Kernel("KeGetCurrentProcessType"));
      worker.Store32(seen+4,0x1234abcd);
    });
    REQUIRE(c.Kernel("ExCreateThread",{out,0,id,0,rex::test::Caller::start_thunk,
                                     context,0x040000a3})==0);
    const u32 pointer=c.Load32(out), thread_id=c.Load32(id);
    REQUIRE(pointer!=0);
    REQUIRE(thread_id!=0);
    REQUIRE(table.GetByAddress(pointer));
    CHECK(c.Kernel("NtClose",{pointer})==X_STATUS_INVALID_HANDLE);
    REQUIRE(c.Kernel("ObOpenObjectByPointer",{pointer,handle_out})==0);
    const u32 handle=c.Load32(handle_out);
    REQUIRE(c.Kernel("KeResumeThread",{pointer})==0);
    REQUIRE(c.Kernel("NtWaitForSingleObjectEx",{handle,1,0,c.AllocQuad(-50000000)})==0);
    CHECK(c.Load32(seen)==kXProcTypeSystem);
    CHECK(c.Load32(seen+4)==0x1234abcd);
    REQUIRE(c.Kernel("NtClose",{handle})==0);
    REQUIRE(table.GetByAddress(pointer));
    c.Kernel("ObDereferenceObject",{pointer});
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while (table.GetByAddress(pointer) && std::chrono::steady_clock::now()<deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    CHECK_FALSE(table.GetByAddress(pointer));
  });
}

REX_TEST_CASE("metro_system_attach: invalid thread output is rejected before starting guest code",
              "[kernel][metro_system_attach]") {
  using namespace rex::kernel;
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    const u32 out=c.Alloc(8);
    c.Store32(out,0xdeadbeef);
    const auto context=rex::test::Caller::RegisterBody([](rex::test::Caller&) {});
    CHECK(c.Kernel("ExCreateThread",{0x7f100000,0,out,0,rex::test::Caller::start_thunk,
                                    context,0x80})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("ExCreateThread",{out,0,0x7f100000,0,rex::test::Caller::start_thunk,
                                    context,0x80})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("ExCreateThread",{out,0,out+2,0,rex::test::Caller::start_thunk,
                                    context,0x80})==X_STATUS_INVALID_PARAMETER);
    CHECK(c.Load32(out)==0xdeadbeef);
  });
}

#include <rex/kernel/types/io.h>

REX_TEST_CASE("metro_system_attach: current-thread pseudo handle survives closure of the creation handle",
              "[kernel][metro_system_attach]") {
  using namespace rex::kernel;
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    const u32 out=c.Alloc(4), observed=c.Alloc(16), event_out=c.Alloc(4), wait_handle=c.Alloc(4);
    const u32 context=rex::test::Caller::RegisterBody([observed](rex::test::Caller& worker) {
      const u32 dup=worker.Alloc(4), object=worker.Alloc(4);
      auto* self=KernelThread::GetCallingThread();
      worker.Store32(observed,self->GetGuestObject());
      worker.Store32(observed+4,worker.Kernel("NtDuplicateObject",{0xfffffffe,dup,0}));
      if (worker.Load32(observed+4)==0) {
        worker.Store32(observed+8,worker.Kernel("ObReferenceObjectByHandle",{worker.Load32(dup),0,object}));
        worker.Store32(observed+12,worker.Load32(object));
        if (worker.Load32(object)) worker.Kernel("ObDereferenceObject",{worker.Load32(object)});
        worker.Kernel("NtClose",{worker.Load32(dup)});
      }
      CHECK(worker.Kernel("NtClose",{0xfffffffe})==X_STATUS_INVALID_HANDLE);
    });
    REQUIRE(c.Kernel("ExCreateThread",{out,0,0,0,rex::test::Caller::start_thunk,context,0x83})==0);
    const u32 pointer=c.Load32(out);
    REQUIRE(pointer);
    // Reuse a handle slot while the new system thread is still suspended.
    REQUIRE(c.Kernel("NtCreateEvent",{event_out,0,0,0})==0);
    REQUIRE(c.Kernel("ObOpenObjectByPointer",{pointer,wait_handle})==0);
    REQUIRE(c.Kernel("KeResumeThread",{pointer})==0);
    REQUIRE(c.Kernel("NtWaitForSingleObjectEx",{c.Load32(wait_handle),1,0,c.AllocQuad(-50000000)})==0);
    CHECK(c.Load32(observed)==pointer);
    CHECK(c.Load32(observed+4)==0);
    CHECK(c.Load32(observed+8)==0);
    CHECK(c.Load32(observed+12)==pointer);
    CHECK(c.Kernel("NtClose",{c.Load32(event_out)+1})==X_STATUS_INVALID_HANDLE);
    CHECK(c.Kernel("NtClose",{c.Load32(event_out)})==0);
    CHECK(c.Kernel("NtClose",{c.Load32(wait_handle)})==0);
    c.Kernel("ObDereferenceObject",{pointer});
  });
}

REX_TEST_CASE("metro_system_attach: overlapped APC targets original pointer-owned thread",
              "[kernel][metro_system_attach]") {
  using namespace rex::kernel;
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    const u32 out=c.Alloc(4), seen=c.Alloc(16), wait_handle=c.Alloc(4), event_out=c.Alloc(4);
    const u32 overlapped=c.Alloc(sizeof(XOVERLAPPED)+4);
    c.Store32(overlapped+sizeof(XOVERLAPPED),seen);
    const u32 routine=StateOf(c.GetRuntime()).GetFunctionDispatcher()->AllocateThunk(
      +[](PPCContext& ctx,u8* base) {
        auto* self=KernelThread::GetCallingThread();
        rex::test::Caller worker(ctx,base,self->GetRuntime());
        const u32 block=ctx.r5.u32;
        const u32 output=worker.Load32(block+sizeof(XOVERLAPPED));
        worker.Store32(output,ctx.r3.u32);
        worker.Store32(output+4,ctx.r4.u32);
        worker.Store32(output+8,self->GetGuestObject());
        worker.Store32(output+12,1);
      },0);
    REQUIRE(routine);
    c.Store32(overlapped+offsetof(XOVERLAPPED,completion_routine),routine);
    const u32 context=rex::test::Caller::RegisterBody([overlapped,seen](rex::test::Caller& worker) {
      StateOf(worker.GetRuntime()).GetOverlappedDispatcher().CompleteDeferred(
        overlapped,[] { return CompletionOptions{.result=0,.length=73}; });
      const u32 delay=worker.AllocQuad(-1000000);
      for (int i=0;i<30 && !worker.Load32(seen+12);++i)
        worker.Kernel("KeDelayExecutionThread",{1,1,delay});
    });
    REQUIRE(c.Kernel("ExCreateThread",{out,0,0,0,rex::test::Caller::start_thunk,context,0x83})==0);
    const u32 pointer=c.Load32(out);
    REQUIRE(pointer);
    REQUIRE(c.Kernel("NtCreateEvent",{event_out,0,0,0})==0);
    REQUIRE(c.Kernel("ObOpenObjectByPointer",{pointer,wait_handle})==0);
    REQUIRE(c.Kernel("KeResumeThread",{pointer})==0);
    REQUIRE(c.Kernel("NtWaitForSingleObjectEx",{c.Load32(wait_handle),1,0,c.AllocQuad(-50000000)})==0);
    CHECK(c.Load32(seen)==0);
    CHECK(c.Load32(seen+4)==73);
    CHECK(c.Load32(seen+8)==pointer);
    CHECK(c.Load32(seen+12)==1);
    CHECK(c.Load32(overlapped+offsetof(XOVERLAPPED,length))==73);
    c.Kernel("NtClose",{c.Load32(event_out)});
    c.Kernel("NtClose",{c.Load32(wait_handle)});
    c.Kernel("ObDereferenceObject",{pointer});
  });
}
