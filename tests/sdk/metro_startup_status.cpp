
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
