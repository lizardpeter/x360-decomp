
#include "kernel_fixture.h"
#include <rex/kernel/types/status.h>
REX_TEST_CASE("metro_startup_status: absent ETX producer cannot create a fake successful registration",
              "[kernel][metro_startup_status]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    const u32 descriptor=c.Alloc(32), schema=c.Alloc(64), registration=c.Alloc(64);
    for (u32 i=0;i<64;i+=4)c.Store32(registration+i,0x12340000u+i);
    const u32 status=c.Kernel("EtxProducerRegister",{descriptor,schema,9,0,64,registration});
    CHECK(status==rex::kernel::X_STATUS_NOT_SUPPORTED);
    CHECK((status&0x80000000u)!=0);
    for (u32 i=0;i<64;i+=4)CHECK(c.Load32(registration+i)==0x12340000u+i);
    CHECK(c.Kernel("EtxProducerRegister",{0,0,0,0,0,0})==rex::kernel::X_STATUS_NOT_SUPPORTED);
  });
}

REX_TEST_CASE("metro_startup_status: unavailable raw dump and empty recorded hardware-error state",
              "[kernel][metro_startup_status]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    const u32 output=c.Alloc(64);
    for (u32 i=0;i<64;i+=4)c.Store32(output+i,0x5A5A0000u+i);
    CHECK(c.Kernel("DumpGetRawDumpInfo",{output,1})==0);
    CHECK(c.Kernel("DumpGetRawDumpInfo",{0,0})==0);
    for (u32 i=0;i<64;i+=4)CHECK(c.Load32(output+i)==0x5A5A0000u+i);
    // The original call consumes no parameters; the result must not
    // inherit whatever was left in r3 by the previous call.
    CHECK(c.Kernel("HalGetNotedArgonErrors",{0xFFFFFFFFu})==0);
    CHECK(c.Kernel("HalGetNotedArgonErrors",{7})==0);
  });
}

REX_TEST_CASE("metro_startup_status: unsupported custom object exports preserve outputs",
              "[kernel][metro_startup_status]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    using namespace rex::kernel;
    const u32 descriptor=c.Alloc(28), object=c.Alloc(48), out=c.Alloc(4);
    c.Store32(out,0xbebebebe);
    CHECK(c.Kernel("ObCreateObject",{descriptor,0,48,out})==X_STATUS_NOT_SUPPORTED);
    CHECK(c.Load32(out)==0xbebebebe);
    CHECK(c.Kernel("ObInsertObject",{object,0,0,out})==X_STATUS_INVALID_HANDLE);
    CHECK(c.Load32(out)==0xbebebebe);
    CHECK(c.Kernel("ObOpenObjectByPointer",{object,0xfffffffc})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("ObLookupThreadByThreadId",{0,0xfffffffc})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("ObReferenceObjectByHandle",{0,0,0xfffffffc})==X_STATUS_ACCESS_VIOLATION);
  });
}


REX_TEST_CASE("metro_startup_status: original counted object names and missing devices",
              "[kernel][metro_startup_status]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    using namespace rex::kernel;
    const u32 out=c.Alloc(4), event_out=c.Alloc(4);
    const u32 attrs=c.AllocAttributes("MetroObjectName");
    const u32 name=c.Load32(attrs+4);
    REQUIRE(c.Kernel("NtCreateEvent",{event_out,attrs,0,0})==0);
    const u32 handle=c.Load32(event_out);
    const u32 expected=c.Alloc(4);
    REQUIRE(c.Kernel("ObReferenceObjectByHandle",{handle,0,expected})==0);
    REQUIRE(c.Kernel("ObReferenceObjectByName",{name,64,0,0,out})==0);
    CHECK(c.Load32(out)==c.Load32(expected));
    const u32 data=c.Alloc(16), returned=c.Alloc(4);
    c.Store32(data,0x11223344); c.Store32(returned,0x55667788);
    CHECK(c.Kernel("IoSynchronousDeviceIoControlRequest",{0x2d001c,c.Load32(out),0,0,data,16,returned,0})==X_STATUS_NOT_SUPPORTED);
    CHECK(c.Load32(data)==0x11223344);
    CHECK(c.Load32(returned)==0x55667788);
    CHECK(c.Kernel("ObDereferenceObject",{c.Load32(out)})==0);
    CHECK(c.Kernel("ObDereferenceObject",{c.Load32(expected)})==0);
    CHECK(c.Kernel("NtClose",{handle})==0);
    const u32 missing=c.Load32(c.AllocAttributes("\\Device\\HdDvdRom")+4);
    c.Store32(out,0xbebebebe);
    CHECK(c.Kernel("ObReferenceObjectByName",{missing,64,0,0,out})==X_STATUS_OBJECT_NAME_NOT_FOUND);
    CHECK(c.Load32(out)==0xbebebebe);
    CHECK(c.Kernel("ObReferenceObjectByName",{0xfffffffc,64,0,0,out})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("ObReferenceObjectByName",{missing,64,0,0,0xfffffffc})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Load32(out)==0xbebebebe);
    const u32 malformed=c.Alloc(8);
    c.Store32(malformed,0x00080004);
    c.Store32(malformed+4,c.AllocString("abcdefgh"));
    CHECK(c.Kernel("ObReferenceObjectByName",{malformed,64,0,0,out})==X_STATUS_OBJECT_NAME_INVALID);
    c.Store32(malformed,0x00040004);
    c.Store32(malformed+4,0xfffffffc);
    CHECK(c.Kernel("ObReferenceObjectByName",{malformed,64,0,0,out})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Load32(out)==0xbebebebe);
    CHECK(c.Kernel("IoSynchronousDeviceIoControlRequest",{0x2d001c,0,0,0,data,16,returned,0})==X_STATUS_INVALID_HANDLE);
    CHECK(c.Kernel("IoSynchronousDeviceIoControlRequest",{0x2d001c,0xbebebebe,0,0,data,16,returned,0})==X_STATUS_INVALID_HANDLE);
    CHECK(c.Load32(data)==0x11223344);
    CHECK(c.Load32(returned)==0x55667788);
  });
}

#include <atomic>
#include <rex/kernel/function_dispatcher.h>
#include <rex/kernel/object/kernel_thread.h>
#include <rex/kernel/title_runtime.h>
#include "kernel/test_access.h"
namespace {
std::atomic<u32> metro_allocs{0}, metro_deletes{0}, metro_frees{0}, metro_size{0}, metro_tag{0}, metro_value{0};
void MetroObjectAllocate(PPCContext& ctx,u8* base) {
  rex::test::Caller c(ctx,base,rex::kernel::KernelThread::GetCallingThread()->GetRuntime());
  ++metro_allocs; metro_size=ctx.r3.u32; metro_tag=ctx.r4.u32;
  ctx.r3.u64=c.Kernel("ExAllocatePoolTypeWithTag",{ctx.r3.u32,ctx.r4.u32,ctx.r5.u32});
}
void MetroObjectDelete(PPCContext& ctx,u8* base) {
  rex::test::Caller c(ctx,base,rex::kernel::KernelThread::GetCallingThread()->GetRuntime());
  ++metro_deletes; metro_value=c.Load32(ctx.r3.u32);
}
void MetroObjectFree(PPCContext& ctx,u8* base) {
  rex::test::Caller c(ctx,base,rex::kernel::KernelThread::GetCallingThread()->GetRuntime());
  ++metro_frees; c.Kernel("ExFreePool",{ctx.r3.u32});
}
}
REX_TEST_CASE("metro_startup_status: custom guest object callbacks and ownership",
              "[kernel][metro_startup_status]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    using namespace rex::kernel;
    metro_allocs=0; metro_deletes=0; metro_frees=0;
    auto& dispatch=GetFunctionDispatcher(c.GetRuntime());
    const u32 alloc=dispatch.AllocateThunk(&MetroObjectAllocate,0);
    const u32 release=dispatch.AllocateThunk(&MetroObjectFree,0);
    const u32 cleanup=dispatch.AllocateThunk(&MetroObjectDelete,0);
    REQUIRE(alloc); REQUIRE(release); REQUIRE(cleanup);
    const u32 type=c.Alloc(28), other=c.Alloc(28), out=c.Alloc(4), h=c.Alloc(4), dup=c.Alloc(4);
    c.Store32(type,alloc); c.Store32(type+4,release); c.Store32(type+12,cleanup);
    c.Store32(type+20,12); c.Store32(type+24,0x66746f4e);
    CHECK(c.Kernel("ObCreateObject",{type,0,48,0xfffffffc})==X_STATUS_ACCESS_VIOLATION);
    CHECK(metro_allocs.load()==0);
    REQUIRE(c.Kernel("ObCreateObject",{type,0,48,out})==0);
    const u32 body=c.Load32(out);
    REQUIRE(body); CHECK(metro_allocs.load()==1);
    CHECK(metro_size.load()==64); CHECK(metro_tag.load()==0x66746f4e);
    CHECK(c.Load32(body-16)==1); CHECK(c.Load32(body-12)==0); CHECK(c.Load32(body-8)==type);
    for(u32 i=0;i<48;i+=4)CHECK(c.Load32(body+i)==0);
    c.Store32(body,0x10203040); c.Store32(h,0xbebebebe);
    CHECK(c.Kernel("ObInsertObject",{body,0,0,0xfffffffc})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("ObInsertObject",{body,0,1,h})==X_STATUS_NOT_SUPPORTED);
    CHECK(c.Load32(h)==0xbebebebe);
    REQUIRE(c.Kernel("ObInsertObject",{body,0,0,h})==0);
    const u32 handle=c.Load32(h);
    CHECK(c.Load32(body-16)==1); CHECK(c.Load32(body-12)==1);
    CHECK(c.Kernel("ObInsertObject",{body,0,0,dup})==X_STATUS_INVALID_HANDLE);
    CHECK(c.Kernel("ObReferenceObjectByHandle",{handle,other,out})==X_STATUS_OBJECT_TYPE_MISMATCH);
    REQUIRE(c.Kernel("ObReferenceObjectByHandle",{handle,type,out})==0);
    CHECK(c.Load32(out)==body); CHECK(c.Load32(body-16)==2);
    REQUIRE(c.Kernel("NtDuplicateObject",{handle,dup,0})==0);
    CHECK(c.Load32(body-16)==3); CHECK(c.Load32(body-12)==2);
    CHECK(c.Kernel("NtClose",{handle})==0);
    CHECK(c.Kernel("NtClose",{c.Load32(dup)})==0);
    CHECK(c.Load32(body-16)==1); CHECK(c.Load32(body-12)==0);
    CHECK(metro_deletes.load()==0); CHECK(metro_frees.load()==0);
    CHECK(c.Kernel("ObDereferenceObject",{body})==0);
    CHECK(metro_deletes.load()==1); CHECK(metro_frees.load()==1);
    CHECK(metro_value.load()==0x10203040);
    CHECK(!c.GetRuntime().GetObjectTable().GetByAddress(body));
    REQUIRE(c.Kernel("ObCreateObject",{type,0,4,out})==0);
    const u32 uninserted=c.Load32(out);
    c.Store32(uninserted,0xaabbccdd);
    CHECK(c.Kernel("ObDereferenceObject",{uninserted})==0);
    CHECK(metro_allocs.load()==2); CHECK(metro_deletes.load()==2); CHECK(metro_frees.load()==2);
    CHECK(metro_value.load()==0xaabbccdd);
  });
}

namespace {
std::atomic<u32> metro_closes{0}, metro_close_first{0}, metro_close_last{0}, metro_close_body{0};
void MetroObjectClose(PPCContext& ctx,u8* base) {
  rex::test::Caller c(ctx,base,rex::kernel::KernelThread::GetCallingThread()->GetRuntime());
  const u32 body=ctx.r3.u32, count=ctx.r4.u32;
  ++metro_closes;
  if (count==2) metro_close_first=c.Load32(body-12);
  if (count==1) {
    metro_close_last=c.Load32(body-12);
    metro_close_body=body;
    // The original 816F1200 callback takes a pointer reference on close.
    c.Kernel("ObReferenceObject",{body});
  }
}
}
REX_TEST_CASE("metro_startup_status: close callback may reference object during final handle closure",
              "[kernel][metro_startup_status]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    using namespace rex::kernel;
    metro_allocs=0; metro_deletes=0; metro_frees=0; metro_closes=0;
    metro_close_first=99; metro_close_last=99; metro_close_body=0;
    auto& dispatch=GetFunctionDispatcher(c.GetRuntime());
    const u32 alloc=dispatch.AllocateThunk(&MetroObjectAllocate,0);
    const u32 release=dispatch.AllocateThunk(&MetroObjectFree,0);
    const u32 cleanup=dispatch.AllocateThunk(&MetroObjectDelete,0);
    const u32 close=dispatch.AllocateThunk(&MetroObjectClose,0);
    REQUIRE(alloc); REQUIRE(release); REQUIRE(cleanup); REQUIRE(close);
    const u32 type=c.Alloc(28), out=c.Alloc(4), h=c.Alloc(4), dup=c.Alloc(4);
    c.Store32(type,alloc); c.Store32(type+4,release); c.Store32(type+8,close);
    c.Store32(type+12,cleanup); c.Store32(type+24,0x66746f4e);
    REQUIRE(c.Kernel("ObCreateObject",{type,0,48,out})==0);
    const u32 body=c.Load32(out); c.Store32(body,0x12345678);
    REQUIRE(c.Kernel("ObInsertObject",{body,0,0,h})==0);
    REQUIRE(c.Kernel("NtDuplicateObject",{c.Load32(h),dup,0})==0);
    CHECK(c.Kernel("NtClose",{c.Load32(h)})==0);
    CHECK(metro_closes.load()==1); CHECK(metro_close_first.load()==1);
    CHECK(c.Load32(body-16)==1);
    CHECK(c.Kernel("NtClose",{c.Load32(dup)})==0);
    CHECK(metro_closes.load()==2); CHECK(metro_close_last.load()==0);
    CHECK(metro_close_body.load()==body); CHECK(c.Load32(body-16)==1);
    CHECK(metro_deletes.load()==0); CHECK(metro_frees.load()==0);
    CHECK(c.Kernel("ObDereferenceObject",{body})==0);
    CHECK(metro_deletes.load()==1); CHECK(metro_frees.load()==1);
    CHECK(metro_value.load()==0x12345678);
    CHECK(!c.GetRuntime().GetObjectTable().GetByAddress(body));
  });
}

REX_TEST_CASE("metro_startup_status: custom waits use embedded and shared event identities",
              "[kernel][metro_startup_status]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    using namespace rex::kernel;
    auto& dispatch=GetFunctionDispatcher(c.GetRuntime());
    const u32 alloc=dispatch.AllocateThunk(&MetroObjectAllocate,0);
    const u32 release=dispatch.AllocateThunk(&MetroObjectFree,0);
    REQUIRE(alloc); REQUIRE(release);
    const u32 type=c.Alloc(28), out=c.Alloc(4), h=c.Alloc(4);
    c.Store32(type,alloc); c.Store32(type+4,release); c.Store32(type+20,12);
    c.Store32(type+24,0x66746f4e);
    REQUIRE(c.Kernel("ObCreateObject",{type,0,48,out})==0);
    const u32 body=c.Load32(out), embedded=body+12;
    // Match retail constructor 816A8A54..816A8A78, including zero size byte.
    c.Store32(embedded,0x01000000); c.Store32(embedded+4,0);
    c.Store32(embedded+8,embedded+8); c.Store32(embedded+12,embedded+8);
    REQUIRE(c.Kernel("ObInsertObject",{body,0,0,h})==0);
    const u32 handle=c.Load32(h), zero=c.AllocQuad(0);
    CHECK(c.Kernel("ObGetWaitableObject",{body})==embedded);
    CHECK(c.Kernel("ObGetWaitableObject",{0})==0);
    CHECK(c.Kernel("ObGetWaitableObject",{body+1})==0);
    CHECK(c.Kernel("ObGetWaitableObject",{0xfffffffc})==0);
    CHECK(c.Kernel("NtWaitForSingleObjectEx",{handle,1,0,zero})==X_STATUS_TIMEOUT);
    c.Kernel("KeSetEvent",{embedded,0,0});
    CHECK(c.Kernel("NtWaitForSingleObjectEx",{handle,1,0,zero})==0);
    CHECK(c.Kernel("NtWaitForSingleObjectEx",{handle,1,0,zero})==X_STATUS_TIMEOUT);
    const u32 array=c.Alloc(4); c.Store32(array,handle);
    CHECK(c.Kernel("NtWaitForMultipleObjectsEx",{1,array,1,1,0,zero})==X_STATUS_TIMEOUT);
    c.Kernel("KeSetEvent",{embedded,0,0});
    CHECK(c.Kernel("NtWaitForMultipleObjectsEx",{1,array,1,1,0,zero})==0);
    CHECK(c.Kernel("NtClose",{handle})==0);
    CHECK(!c.GetRuntime().GetObjectTable().GetByAddress(embedded));
    // Three retail types reference one shared initialized event. Use the
    // fixture's actual guest memory and dispatch rather than a fake signal.
    const u32 shared=c.Kernel("MmAllocatePhysicalMemory",{0,4096,4});
    REQUIRE(shared); REQUIRE((shared&0x80000000u)!=0);
    c.Kernel("KeInitializeEvent",{shared,1,1});
    c.Store32(type+20,shared);
    const u32 h2=c.Alloc(4);
    REQUIRE(c.Kernel("ObCreateObject",{type,0,4,out})==0);
    CHECK(c.Kernel("ObGetWaitableObject",{c.Load32(out)})==shared);
    REQUIRE(c.Kernel("ObInsertObject",{c.Load32(out),0,0,h})==0);
    REQUIRE(c.Kernel("ObCreateObject",{type,0,4,out})==0);
    CHECK(c.Kernel("ObGetWaitableObject",{c.Load32(out)})==shared);
    REQUIRE(c.Kernel("ObInsertObject",{c.Load32(out),0,0,h2})==0);
    CHECK(c.Kernel("NtWaitForSingleObjectEx",{c.Load32(h),1,0,zero})==0);
    CHECK(c.Kernel("NtWaitForSingleObjectEx",{c.Load32(h2),1,0,zero})==X_STATUS_TIMEOUT);
    c.Kernel("KeSetEvent",{shared,0,0});
    CHECK(c.Kernel("NtWaitForSingleObjectEx",{c.Load32(h2),1,0,zero})==0);
    CHECK(c.Kernel("NtClose",{c.Load32(h)})==0);
    CHECK(c.Kernel("NtClose",{c.Load32(h2)})==0);
    CHECK(c.GetRuntime().GetObjectTable().GetByAddress(shared));
    c.GetRuntime().GetObjectTable().ForgetAddress(shared);
    c.Kernel("MmFreePhysicalMemory",{0,shared});
    // An out-of-range relative offset is never treated as signaled.
    c.Store32(type+20,12);
    REQUIRE(c.Kernel("ObCreateObject",{type,0,4,out})==0);
    REQUIRE(c.Kernel("ObInsertObject",{c.Load32(out),0,0,h})==0);
    CHECK(c.Kernel("ObGetWaitableObject",{c.Load32(out)})==0);
    CHECK(c.Kernel("NtWaitForSingleObjectEx",{c.Load32(h),1,0,zero})==X_STATUS_OBJECT_TYPE_MISMATCH);
    CHECK(c.Kernel("NtClose",{c.Load32(h)})==0);
  });
}

REX_TEST_CASE("metro_startup_status: typed missing optical device follows original absent-device branch",
              "[kernel][metro_startup_status]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    using namespace rex::kernel;
    const u32 h=c.Alloc(4), out=c.Alloc(4);
    REQUIRE(c.Kernel("NtCreateEvent",{h,0,0,0})==0);
    REQUIRE(c.Kernel("ObReferenceObjectByHandle",{c.Load32(h),0,out})==0);
    const u32 body=c.Load32(out);
    const u32 event_type=c.Load32(body-8);
    const u32 device_type=event_type - offsetof(KernelGuestGlobals, ExEventObjectType) +
        offsetof(KernelGuestGlobals, IoDeviceObjectType);
    CHECK(c.Kernel("ObDereferenceObject",{body})==0);
    CHECK(c.Kernel("NtClose",{c.Load32(h)})==0);
    const u32 name=c.Load32(c.AllocAttributes("\\Device\\HdDvdRom")+4);
    c.Store32(out,0xbebebebe);
    CHECK(c.Kernel("ObReferenceObjectByName",{name,0,device_type,0,out})==X_STATUS_NO_SUCH_DEVICE);
    CHECK(c.Load32(out)==0);
    c.Store32(out,0x12345678);
    CHECK(c.Kernel("ObReferenceObjectByName",{name,0,0,0,out})==X_STATUS_OBJECT_NAME_NOT_FOUND);
    CHECK(c.Load32(out)==0x12345678);
  });
}

REX_TEST_CASE("metro_startup_status: native display identity and offline raw NIC",
              "[kernel][metro_startup_status]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    using namespace rex::kernel;
    for (const u32 residue : {0u,1u,5u,0xFFFFFFFFu,0x81B5B5E4u}) {
      CHECK(c.Kernel("HalGetCurrentAVPack",{residue})==8);
      CHECK(c.Kernel("NicGetLinkState",{residue})==0);
    }
    const u32 out=c.Alloc(16), size=c.Alloc(4);
    c.Store32(out,0xAABBCCDD);c.Store32(out+4,0x11223344);
    c.Store32(size,4);
    CHECK(c.Kernel("NicGetOpt",{0,10035,out,size})==X_STATUS_NOT_SUPPORTED);
    CHECK(c.Load32(out)==0xAABBCCDD);
    CHECK(c.Load32(out+4)==0x11223344);
    CHECK(c.Load32(size)==4);
    CHECK(c.Kernel("NicSetOpt",{0,10035,out,4})==X_STATUS_NOT_SUPPORTED);
    CHECK(c.Kernel("NicGetOpt",{0,10035,0xFFFFFFFFu,0xFFFFFFFFu})==X_STATUS_NOT_SUPPORTED);
    CHECK(c.Load32(out)==0xAABBCCDD);
  });
}
REX_TEST_CASE("metro_startup_status: empty hosted failed-device queue initializes exactly one DWORD",
              "[kernel][metro_startup_status]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    using namespace rex::kernel;
    const u32 buffer=c.Alloc(16);
    c.Store32(buffer,0xCAFEBABE);c.Store32(buffer+4,0xFFFFFFFF);
    c.Store32(buffer+8,0xDEADBEEF);c.Store32(buffer+12,0x11223344);
    REQUIRE(c.Kernel("XInputdGetFailedConnectionOrBind",{buffer+4})==0);
    CHECK(c.Load32(buffer+4)==0);
    CHECK(c.Load32(buffer)==0xCAFEBABE);
    CHECK(c.Load32(buffer+8)==0xDEADBEEF);
    CHECK(c.Load32(buffer+12)==0x11223344);
    CHECK(c.Kernel("XInputdGetFailedConnectionOrBind",{0})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("XInputdGetFailedConnectionOrBind",{0xFFFFFFFFu})==X_STATUS_ACCESS_VIOLATION);
    c.Store32(buffer+4,0x12345678);
    REQUIRE(c.Kernel("XInputdGetFailedConnectionOrBind",{buffer+4})==0);
    CHECK(c.Load32(buffer+4)==0);
  });
}

REX_TEST_CASE("metro_startup_status: unload disarms guest object callbacks after original modules are gone",
              "[kernel][metro_startup_status]") {
  using namespace rex::kernel;
  rex::test::KernelFixture fixture;
  metro_allocs=0; metro_deletes=0; metro_frees=0;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    auto& dispatch=GetFunctionDispatcher(c.GetRuntime());
    const u32 alloc=dispatch.AllocateThunk(&MetroObjectAllocate,0);
    const u32 release=dispatch.AllocateThunk(&MetroObjectFree,0);
    const u32 cleanup=dispatch.AllocateThunk(&MetroObjectDelete,0);
    REQUIRE(alloc); REQUIRE(release); REQUIRE(cleanup);
    const u32 type=c.Alloc(28), out=c.Alloc(4), h=c.Alloc(4);
    c.Store32(type,alloc); c.Store32(type+4,release); c.Store32(type+12,cleanup);
    c.Store32(type+24,0x66746f4e);
    REQUIRE(c.Kernel("ObCreateObject",{type,0,32,out})==0);
    REQUIRE(c.Kernel("ObInsertObject",{c.Load32(out),0,0,h})==0);
    REQUIRE(c.Load32(h));
    CHECK(metro_allocs.load()==1);
    CHECK(metro_deletes.load()==0);
    CHECK(metro_frees.load()==0);
    // Leave an original custom object live deliberately. Bulk title unload
    // must not re-enter guest code after guest threads/modules are gone.
  });
  REQUIRE_FALSE(KernelThread::IsInThread());
  fixture.GetRuntime().Unload();
  CHECK_FALSE(fixture.GetRuntime().IsLoaded());
  CHECK(metro_deletes.load()==0);
  CHECK(metro_frees.load()==0);
}


REX_TEST_CASE("metro_startup_status: absent extended key provider fails closed without output writes",
              "[kernel][metro_startup_status]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    using namespace rex::kernel;
    const u32 output=c.Alloc(64),length=c.Alloc(4);
    c.Store32(length,40);
    for (u32 i=0;i<64;i+=4)c.Store32(output+i,0x5A5A1000u+i);
    for (const u32 id:{0u,0x100u,0xffffffffu}) {
      const u32 status=c.Kernel("XeKeysExGetKey",{id,output,length,0});
      CHECK(status==X_STATUS_NOT_SUPPORTED);
      CHECK((status&0x80000000u)!=0);
      CHECK(c.Load32(length)==40);
      for (u32 i=0;i<64;i+=4)CHECK(c.Load32(output+i)==0x5A5A1000u+i);
    }
    CHECK(c.Kernel("XeKeysExGetKey",{0x100,0,0,0})==X_STATUS_NOT_SUPPORTED);
  });
}


REX_TEST_CASE("metro_startup_status: waitable object address borrows actual dispatcher without adding references",
              "[kernel][metro_startup_status]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    using namespace rex::kernel;
    const u32 h=c.Alloc(4),out=c.Alloc(4);
    REQUIRE(c.Kernel("NtCreateEvent",{h,0,0,0})==0);
    const u32 handle=c.Load32(h);
    REQUIRE(c.Kernel("ObReferenceObjectByHandle",{handle,0,out})==0);
    const u32 event=c.Load32(out);
    REQUIRE(event);
    CHECK(c.Kernel("ObGetWaitableObject",{event})==event);
    CHECK(c.Kernel("ObGetWaitableObject",{event})==event);
    CHECK(c.Kernel("ObGetWaitableObject",{handle})==0);
    CHECK(c.Kernel("NtClose",{handle})==0);
    CHECK(c.Kernel("ObGetWaitableObject",{event})==event);
    CHECK(c.Kernel("ObDereferenceObject",{event})==0);
    CHECK(!c.GetRuntime().GetObjectTable().GetByAddress(event));
    CHECK(c.Kernel("ObGetWaitableObject",{event})==0);
  });
}
