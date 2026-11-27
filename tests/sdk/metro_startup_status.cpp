
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
