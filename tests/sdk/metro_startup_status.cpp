
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
    CHECK(c.Kernel("ObInsertObject",{object,0,0,out})==X_STATUS_NOT_SUPPORTED);
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
    const u32 data=c.Alloc(16), returned=c.Alloc(4);
    c.Store32(data,0x11223344); c.Store32(returned,0x55667788);
    CHECK(c.Kernel("IoSynchronousDeviceIoControlRequest",{0x2d001c,0,0,0,data,16,returned,0})==X_STATUS_INVALID_HANDLE);
    CHECK(c.Kernel("IoSynchronousDeviceIoControlRequest",{0x2d001c,0xbebebebe,0,0,data,16,returned,0})==X_STATUS_INVALID_HANDLE);
    CHECK(c.Load32(data)==0x11223344);
    CHECK(c.Load32(returned)==0x55667788);
  });
}
