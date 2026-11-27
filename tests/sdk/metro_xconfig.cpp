
#include "kernel_fixture.h"
#include <rex/kernel/types/status.h>
#include <rex/kernel/guest_memory.h>
#include <rex/kernel/title_runtime.h>

REX_TEST_CASE("metro_xconfig: console preference widths and read-write round trips",
              "[kernel][metro_xconfig]") {
  rex::test::KernelFixture fixture;
  fixture.RunOnGuestThread([](rex::test::Caller& c) {
    const u32 buffer=c.Alloc(8), required=c.Alloc(4);
    struct Case {u32 selector,width,initial,replacement;};
    const Case cases[]={
      {1,2,0x1000,0x000a},
      {2,2,0,0x0168},
      {4,4,1,0x1234},
      {7,2,0,1},
      {0x12,1,0,1},
      {0x13,4,0,0x12345678},
    };
    auto get=[&](u32 selector,u32 ptr,u32 size,u32 length) {
      return c.Kernel("ExGetXConfigSetting",{7,selector,ptr,size,length});
    };
    auto set=[&](u32 selector,u32 ptr,u32 size) {
      return c.Kernel("ExSetXConfigSetting",{7,selector,ptr,size});
    };
    auto value=[&](u32 width) {
      u32 n=0;
      for(u32 i=0;i<width;++i)n=(n<<8)|c.Load8(buffer+i);
      return n;
    };
    for(auto item:cases) {
      INFO(item.selector);
      c.Store32(buffer,0xdeadbeef); c.Store32(required,0xabcd1234);
      REQUIRE(get(item.selector,0,0,required)==0);
      CHECK(c.Load32(required)==(item.width<<16|0x1234));
      REQUIRE(get(item.selector,buffer,item.width,required)==0);
      CHECK(value(item.width)==item.initial);
      CHECK(c.Load8(buffer+item.width)==(item.width==1?0xad:item.width==2?0xbe:0));
      c.Store32(buffer,item.replacement<<(8*(4-item.width)));
      REQUIRE(set(item.selector,buffer,item.width)==0);
      c.Store32(buffer,0);
      REQUIRE(get(item.selector,buffer,item.width,required)==0);
      CHECK(value(item.width)==item.replacement);
      c.Store32(buffer,0xdeadbeef);
      CHECK(get(item.selector,buffer,item.width-1,required)==rex::kernel::X_STATUS_BUFFER_TOO_SMALL);
      CHECK(c.Load32(buffer)==0xdeadbeef);
      CHECK(set(item.selector,buffer,item.width+1)==rex::kernel::X_STATUS_INVALID_PARAMETER);
      REQUIRE(get(item.selector,buffer,item.width,required)==0);
      CHECK(value(item.width)==item.replacement);
    }
    CHECK(get(1,0,2,required)==rex::kernel::X_STATUS_INVALID_PARAMETER_3);
    CHECK(get(0xffff,buffer,4,required)==rex::kernel::X_STATUS_INVALID_PARAMETER_2);
    c.Store32(buffer,0xdeadbeef);
    CHECK(get(1,buffer,2,0xfffffffc)==rex::kernel::X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Load32(buffer)==0xdeadbeef);
    CHECK(get(1,0xfffffffc,2,required)==rex::kernel::X_STATUS_ACCESS_VIOLATION);
    CHECK(get(1,buffer,2,buffer)==rex::kernel::X_STATUS_INVALID_PARAMETER);
    CHECK(c.Load32(buffer)==0xdeadbeef);
    CHECK(set(1,0xfffffffc,2)==rex::kernel::X_STATUS_ACCESS_VIOLATION);
    CHECK(set(1,buffer,2)==rex::kernel::X_STATUS_INVALID_PARAMETER);
    CHECK(c.Kernel("ExSetXConfigSetting",{2,2,buffer,4})==rex::kernel::X_STATUS_INVALID_PARAMETER_1);
    REQUIRE(get(1,buffer,2,required)==0);
    CHECK(value(2)==0xa);
    // Restore app preference defaults after the test.
    for(auto item:cases) {
      c.Store32(buffer,item.initial<<(8*(4-item.width)));
      REQUIRE(set(item.selector,buffer,item.width)==0);
    }
  });
}
