
// Authored Metro runtime regression cases using the pinned SDK's actual
// guest-thread, export-call, mapped memory and filesystem fixture.
REX_TEST_CASE("metro_io_runtime: device controls reject unsupported and invalid buffers",
              "[kernel][files][metro_io_runtime]") {
  KernelFixture fixture([](const std::filesystem::path& root) {
    WriteScratch(root, "device.bin", 32);
  });
  MountScratch(fixture);
  fixture.RunOnGuestThread([](Caller& c) {
    const u32 handle_ptr = c.Alloc(4);
    const u32 iosb = c.Alloc(8);
    REQUIRE(c.Kernel("NtCreateFile",
        {handle_ptr, kReadWriteAccess, c.AllocAttributes("scratch:\\device.bin"),
         iosb, 0, 0, 3, 1, 0x20}) == 0);
    const u32 handle = c.Load32(handle_ptr);
    const u32 output = rex::test::PutFilled(c, 32);
    const u32 input = rex::test::PutFilled(c, 32);
    const u32 event = NewEvent(c);
    auto reset = [&] {
      c.Store32(iosb, 0x12345678);
      c.Store32(iosb+4, 0xabcdef01);
      c.Store32(output, 0xdeadbeef);
      c.Store32(output+4, 0xcafebabe);
    };
    auto unchanged = [&] {
      CHECK(c.Load32(iosb) == 0x12345678);
      CHECK(c.Load32(iosb+4) == 0xabcdef01);
      CHECK(c.Load32(output) == 0xdeadbeef);
      CHECK(c.Load32(output+4) == 0xcafebabe);
      CHECK(c.Kernel("NtWaitForSingleObjectEx", {event, 1, 0, c.AllocQuad(0)}) ==
            rex::kernel::X_STATUS_TIMEOUT);
    };
    reset();
    for (u32 code : {0x4D028u, 0x24010u, 0x2D000Cu, 0xFFFFFFFFu}) {
      CHECK(c.Kernel("NtDeviceIoControlFile",
            {handle, event, 0, 0, iosb, code, input, 32, output, 32}) ==
            rex::kernel::X_STATUS_NOT_SUPPORTED);
      unchanged();
    }
    CHECK(c.Kernel("NtDeviceIoControlFile",
          {handle, event, 0, 0, iosb, 0x70000, 0, 0, output, 4}) ==
          rex::kernel::X_STATUS_BUFFER_TOO_SMALL);
    unchanged();
    CHECK(c.Kernel("NtDeviceIoControlFile",
          {handle, event, 0, 0, iosb, 0x70000, 0, 0, 0, 8}) ==
          rex::kernel::X_STATUS_ACCESS_VIOLATION);
    unchanged();
    CHECK(c.Kernel("NtDeviceIoControlFile",
          {handle, event, 0, 0, iosb, 0x70000, 0, 0, iosb, 8}) ==
          rex::kernel::X_STATUS_INVALID_PARAMETER);
    unchanged();
    CHECK(c.Kernel("NtDeviceIoControlFile",
          {handle, 0x1234, 0, 0, iosb, 0x70000, 0, 0, output, 8}) ==
          rex::kernel::X_STATUS_INVALID_HANDLE);
    unchanged();
    CHECK(c.Kernel("NtDeviceIoControlFile",
          {handle, event, 0, 0, iosb, 0x70000, 0, 0, output, 8}) == 0);
    CHECK(c.Load32(output) == 0x7f8);
    CHECK(c.Load32(output+4) == 512);
    CHECK(c.Load32(iosb) == 0);
    CHECK(c.Load32(iosb+4) == 8);
    CHECK(c.Kernel("NtWaitForSingleObjectEx", {event, 1, 0, c.AllocQuad(0)}) == 0);
    CHECK(c.Kernel("NtDeviceIoControlFile",
          {handle, 0, 0, 0, iosb, 0x74004, 0, 0, output, 16}) == 0);
    CHECK(c.Load32(output) == 0);
    CHECK(c.Load32(output+4) == 0);
    CHECK(c.Load32(output+8) == 0);
    CHECK(c.Load32(output+12) == 0xff000);
    CHECK(c.Load32(iosb+4) == 16);
    CHECK(c.Kernel("NtClose", {event}) == 0);
    CHECK(c.Kernel("NtClose", {handle}) == 0);
  });
}

REX_TEST_CASE("metro_io_runtime: explicit read and write positions own the shared cursor",
              "[kernel][files][metro_io_runtime]") {
  KernelFixture fixture([](const std::filesystem::path& root) {
    std::filesystem::create_directories(root / "scratch");
    std::ofstream out(root / "scratch" / "cursor.bin", std::ios::binary);
    const char bytes[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    out.write(bytes,sizeof(bytes));
  });
  MountScratch(fixture);
  fixture.RunOnGuestThread([](Caller& c) {
    const u32 h = c.Alloc(4), iosb = c.Alloc(8), data = c.Alloc(16);
    REQUIRE(c.Kernel("NtCreateFile",
        {h, kReadWriteAccess, c.AllocAttributes("scratch:\\cursor.bin"),
         iosb, 0, 0, 3, 1, 0x20}) == 0);
    const u32 handle=c.Load32(h);
    auto read = [&](u32 offset) {
      return c.Kernel("NtReadFile", {handle,0,0,0,iosb,data,4,offset});
    };
    REQUIRE(read(c.AllocQuad(8)) == 0);
    CHECK(c.Load32(data) == 0x08090a0b);
    REQUIRE(read(c.AllocQuad(0)) == 0);
    CHECK(c.Load32(data) == 0x00010203);
    REQUIRE(read(0) == 0);
    CHECK(c.Load32(data) == 0x04050607);
    c.Store32(data,0xdeadbeef);
    REQUIRE(c.Kernel("NtWriteFile", {handle,0,0,0,iosb,data,4,c.AllocQuad(0)}) == 0);
    REQUIRE(read(0) == 0);
    CHECK(c.Load32(data) == 0x04050607);
    REQUIRE(read(c.AllocQuad(0)) == 0);
    CHECK(c.Load32(data) == 0xdeadbeef);
    // A failed pointer check must not consume the file cursor.
    CHECK(c.Kernel("NtReadFile", {handle,0,0,0,iosb,data,4,0xFFFFFFFC}) ==
          rex::kernel::X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("NtReadFile", {handle,0,0,0,0xFFFFFFFC,data,4,0}) ==
          rex::kernel::X_STATUS_ACCESS_VIOLATION);
    REQUIRE(read(0) == 0);
    CHECK(c.Load32(data) == 0x04050607);
    CHECK(c.Kernel("NtClose", {handle}) == 0);
  });
}
