
REX_TEST_CASE("metro_vm: original XAM heap reserve query commit protect release", "[kernel][metro_vm]") {
  KernelFixture fixture;
  fixture.RunOnGuestThread([](Caller& c) {
    const u32 a=c.Alloc(4), n=c.Alloc(4), old=c.Alloc(4), info=c.Alloc(28);
    c.Store32(a,0); c.Store32(n,0x30000);
    REQUIRE(c.Kernel("NtAllocateVirtualMemory",{a,n,0x60002000,4,3})==0);
    const u32 base=c.Load32(a);
    REQUIRE(base!=0);
    REQUIRE(c.Kernel("NtQueryVirtualMemory",{base,info,3})==0);
    CHECK(c.Load32(info)==base);
    CHECK(c.Load32(info+16)==0x2000);
    c.Store32(n,0x10000);
    REQUIRE(c.Kernel("NtAllocateVirtualMemory",{a,n,0x60001000,4,3})==0);
    c.Store32(base+0x100,0x11223344);
    c.Store32(a,base+0x8000); c.Store32(n,0x10000);
    REQUIRE(c.Kernel("NtAllocateVirtualMemory",{a,n,0x60001000,4,3})==0);
    CHECK(c.Load32(a)==base);
    CHECK(c.Load32(n)==0x20000);
    CHECK(c.Load32(base+0x100)==0x11223344);
    CHECK(c.Load32(base+0x10000)==0);
    c.Store32(a,base+0xffff); c.Store32(n,2);
    REQUIRE(c.Kernel("NtProtectVirtualMemory",{a,n,2,old,3})==0);
    CHECK(c.Load32(a)==base);
    CHECK(c.Load32(n)==0x20000);
    CHECK(c.Load32(old)==4);
    REQUIRE(c.Kernel("NtQueryVirtualMemory",{base+0x10000,info,3})==0);
    CHECK(c.Load32(info+20)==2);
    c.Store32(a,base); c.Store32(n,0x20000);
    REQUIRE(c.Kernel("NtProtectVirtualMemory",{a,n,4,old,3})==0);
    CHECK(c.Load32(old)==2);
    c.Store32(a,base); c.Store32(n,0x20000);
    REQUIRE(c.Kernel("NtFreeVirtualMemory",{a,n,0x4000,3})==0);
    c.Store32(a,base); c.Store32(n,0);
    REQUIRE(c.Kernel("NtFreeVirtualMemory",{a,n,0x8000,3})==0);
  });
}

REX_TEST_CASE("metro_vm: invalid pointers ranges and selectors fail without writing output", "[kernel][metro_vm]") {
  KernelFixture fixture;
  fixture.RunOnGuestThread([](Caller& c) {
    const u32 a=c.Alloc(4), n=c.Alloc(4), info=c.Alloc(28);
    c.Store32(a,0); c.Store32(n,0x10000);
    CHECK(c.Kernel("NtAllocateVirtualMemory",{a,n,0x3000,4,4})==rex::kernel::X_STATUS_INVALID_PARAMETER);
    CHECK(c.Load32(a)==0);
    CHECK(c.Kernel("NtAllocateVirtualMemory",{a,a,0x3000,4,3})==rex::kernel::X_STATUS_INVALID_PARAMETER);
    CHECK(c.Kernel("NtAllocateVirtualMemory",{0x7f100000,n,0x3000,4,3})==rex::kernel::X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("NtFreeVirtualMemory",{0,n,0x8000,3})==rex::kernel::X_STATUS_INVALID_PARAMETER);
    CHECK(c.Kernel("NtProtectVirtualMemory",{a,n,4,a,3})==rex::kernel::X_STATUS_INVALID_PARAMETER);
    REQUIRE(c.Kernel("NtAllocateVirtualMemory",{a,n,0x60003000,4,3})==0);
    const u32 base=c.Load32(a);
    c.Store32(info,0xDEADBEEF);
    CHECK(c.Kernel("NtQueryVirtualMemory",{base,info,4})==rex::kernel::X_STATUS_INVALID_PARAMETER);
    CHECK(c.Load32(info)==0xDEADBEEF);
    CHECK(c.Kernel("NtQueryVirtualMemory",{base,0x7f100000,3})==rex::kernel::X_STATUS_ACCESS_VIOLATION);
    c.Store32(n,0xffffffff);
    CHECK(c.Kernel("NtProtectVirtualMemory",{a,n,2,0,3})==rex::kernel::X_STATUS_INVALID_PARAMETER);
    CHECK(c.Load32(n)==0xffffffff);
    c.Store32(n,0);
    CHECK(c.Kernel("NtFreeVirtualMemory",{a,n,0x8000,3})==0);
  });
}
