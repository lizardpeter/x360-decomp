
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


REX_TEST_CASE("metro_io_runtime: checked create arguments and honest dismount status",
              "[kernel][files][metro_io_runtime]") {
  KernelFixture fixture([](const std::filesystem::path& root) {
    WriteScratch(root, "storage.bin", 32);
  });
  MountScratch(fixture);
  fixture.RunOnGuestThread([](Caller& c) {
    const u32 h=c.Alloc(4), iosb=c.Alloc(8);
    const u32 attrs=c.AllocAttributes("scratch:\\storage.bin");
    const u32 name=c.Load32(attrs+4);
    auto open=[&](u32 out,u32 attributes,u32 status) {
      return c.Kernel("NtCreateFile",
          {out,kReadWriteAccess,attributes,status,0,0,3,1,0x20});
    };
    auto unchanged=[&] {
      CHECK(c.Load32(h)==0xdeadbeef);
      CHECK(c.Load32(iosb)==0x12345678);
      CHECK(c.Load32(iosb+4)==0xabcdef01);
    };
    c.Store32(h,0xdeadbeef); c.Store32(iosb,0x12345678);
    c.Store32(iosb+4,0xabcdef01);
    CHECK(open(0,attrs,iosb)==rex::kernel::X_STATUS_INVALID_PARAMETER);
    unchanged();
    CHECK(open(0xfffffffc,attrs,iosb)==rex::kernel::X_STATUS_ACCESS_VIOLATION);
    unchanged();
    CHECK(open(h,0xfffffffc,iosb)==rex::kernel::X_STATUS_ACCESS_VIOLATION);
    unchanged();
    CHECK(open(h,attrs,0xfffffffc)==rex::kernel::X_STATUS_ACCESS_VIOLATION);
    unchanged();
    CHECK(open(iosb,attrs,iosb)==rex::kernel::X_STATUS_INVALID_PARAMETER);
    unchanged();
    c.Store32(attrs+4,0xfffffffc);
    CHECK(open(h,attrs,iosb)==rex::kernel::X_STATUS_ACCESS_VIOLATION);
    unchanged();
    c.Store32(attrs+4,name);
    const u32 name_header=c.Load32(name);
    const u32 name_data=c.Load32(name+4);
    c.Store32(name,0x00020001);
    CHECK(open(h,attrs,iosb)==rex::kernel::X_STATUS_INVALID_PARAMETER);
    unchanged();
    c.Store32(name,name_header);
    c.Store32(name+4,0xfffffffc);
    CHECK(open(h,attrs,iosb)==rex::kernel::X_STATUS_ACCESS_VIOLATION);
    unchanged();
    c.Store32(name+4,name_data);
    REQUIRE(open(h,attrs,iosb)==0);
    const u32 handle=c.Load32(h);
    CHECK(c.Kernel("IoDismountVolumeByFileHandle",{0x1234})==
          rex::kernel::X_STATUS_INVALID_HANDLE);
    const u32 event=NewEvent(c);
    CHECK(c.Kernel("IoDismountVolumeByFileHandle",{event})==
          rex::kernel::X_STATUS_OBJECT_TYPE_MISMATCH);
    CHECK(c.Kernel("IoDismountVolumeByFileHandle",{handle})==
          rex::kernel::X_STATUS_NOT_SUPPORTED);
    CHECK(c.Kernel("IoDismountVolumeByName",{0})==
          rex::kernel::X_STATUS_INVALID_PARAMETER);
    CHECK(c.Kernel("IoDismountVolumeByName",{0xfffffffc})==
          rex::kernel::X_STATUS_ACCESS_VIOLATION);
    // Dismount failure must not invalidate a live file.
    const u32 data=c.Alloc(4);
    CHECK(c.Kernel("NtReadFile",{handle,0,0,0,iosb,data,4,0})==0);
    CHECK(c.Kernel("NtClose",{event})==0);
    CHECK(c.Kernel("NtClose",{handle})==0);
  });
}

REX_TEST_CASE("metro_io_runtime: unsupported storage stream never reports a fabricated event",
              "[kernel][files][metro_io_runtime]") {
  KernelFixture fixture;
  fixture.RunOnGuestThread([](Caller& c) {
    const u32 notification = c.Alloc(32);
    for (u32 offset = 0; offset < 32; offset += 4)
      c.Store32(notification + offset, 0x12340000u + offset);
    for (int attempt = 0; attempt < 2; ++attempt) {
      const u32 status = c.Kernel("DrvGetContentStorageNotification", {notification});
      CHECK(status == rex::kernel::X_STATUS_NOT_SUPPORTED);
      CHECK((status & 0x80000000u) != 0);
      for (u32 offset = 0; offset < 32; offset += 4)
        CHECK(c.Load32(notification + offset) == 0x12340000u + offset);
    }
    CHECK(c.Kernel("DrvGetContentStorageNotification", {0}) ==
          rex::kernel::X_STATUS_INVALID_PARAMETER);
  });
}

REX_TEST_CASE("metro_io_runtime: isolated writable cache via physical path and game alias",
              "[kernel][files][metro_io_runtime]") {
  KernelFixture fixture([](const std::filesystem::path& root) {
    std::filesystem::create_directories(root/"cache-provider");
    std::ofstream(root/"immutable.bin",std::ios::binary) << "firmware";
  });
  namespace fs=rex::filesystem;
  auto& mounts=fixture.GetRuntime().GetFileSystem();
  REQUIRE(mounts.Mount({"\\Device\\MetroHddCache",fs::ProviderType::kHostDirectory,
                        fixture.GetRoot()/"cache-provider",fs::MountFlags::kWritable,{}}));
  REQUIRE(mounts.Link("\\Device\\Harddisk0\\Partition1\\Cache","\\Device\\MetroHddCache"));
  REQUIRE(mounts.Stat("\\Device\\Harddisk0\\Partition1\\Cache"));
  REQUIRE(mounts.Stat("game:\\Cache"));
  fixture.RunOnGuestThread([](Caller& c) {
    const u32 h=c.Alloc(4), iosb=c.Alloc(8), data=c.Alloc(4);
    c.Store32(data,0x11223344);
    REQUIRE(c.Kernel("NtCreateFile",
        {h,kReadWriteAccess,c.AllocAttributes("\\Device\\Harddisk0\\Partition1\\Cache\\entry.bin"),
         iosb,0,0,3,3,0x20})==0);
    REQUIRE(c.Kernel("NtWriteFile",{c.Load32(h),0,0,0,iosb,data,4,0})==0);
    REQUIRE(c.Kernel("NtClose",{c.Load32(h)})==0);
    REQUIRE(c.Kernel("NtCreateFile",
        {h,0x80100000,c.AllocAttributes("game:\\Cache\\entry.bin"),iosb,0,0,3,1,0x20})==0);
    REQUIRE(c.Kernel("NtReadFile",{c.Load32(h),0,0,0,iosb,data,4,0})==0);
    CHECK(c.Load32(data)==0x11223344);
    REQUIRE(c.Kernel("NtClose",{c.Load32(h)})==0);
  });
  CHECK(std::filesystem::file_size(fixture.GetRoot()/"cache-provider"/"entry.bin")==4);
  CHECK_FALSE(std::filesystem::exists(fixture.GetRoot()/"Cache"/"entry.bin"));
  CHECK(std::filesystem::file_size(fixture.GetRoot()/"immutable.bin")==8);
}

REX_TEST_CASE("metro_io_runtime: resource file metadata is populated and bounded",
              "[kernel][files][metro_io_runtime]") {
  KernelFixture fixture([](const std::filesystem::path& root) {
    WriteScratch(root,"metadata.bin",64);
  });
  MountScratch(fixture);
  fixture.RunOnGuestThread([](Caller& c) {
    using namespace rex::kernel;
    const u32 h=c.Alloc(4),iosb=c.Alloc(8),out=c.Alloc(64);
    REQUIRE(c.Kernel("NtCreateFile",{h,kReadWriteAccess,c.AllocAttributes("scratch:\\metadata.bin"),
         iosb,0,0,3,1,0x20})==0);
    const u32 handle=c.Load32(h);
    for(u32 off=0;off<64;off+=4)c.Store32(out+off,0xDEADBEEF);
    REQUIRE(c.Kernel("NtQueryInformationFile",{handle,iosb,out,64,4})==0);
    CHECK(c.Load32(iosb+4)==40);
    CHECK(c.Load32(out+40)==0xDEADBEEF);
    REQUIRE(c.Kernel("NtQueryInformationFile",{handle,iosb,out,64,19})==0);
    CHECK(c.Load32(iosb+4)==8);
    CHECK(c.Load32(out+4)>=64);
    CHECK(c.Load32(out+40)==0xDEADBEEF);
    CHECK(c.Kernel("NtQueryInformationFile",{handle,iosb,0xfffffffc,40,4})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("NtQueryInformationFile",{handle,0xfffffffc,out,40,4})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("NtQueryInformationFile",{handle,out+4,out,40,4})==X_STATUS_INVALID_PARAMETER);
    CHECK(c.Kernel("NtQueryInformationFile",{handle,iosb,out,7,19})==X_STATUS_INFO_LENGTH_MISMATCH);
    CHECK(c.Kernel("NtClose",{handle})==0);
  });
}
REX_TEST_CASE("metro_io_runtime: scatter explicit zero and short read preserve exact cursor",
              "[kernel][files][metro_io_runtime]") {
  KernelFixture fixture([](const std::filesystem::path& root) {
    std::filesystem::create_directories(root/"scratch");
    std::ofstream out(root/"scratch"/"scatter.bin",std::ios::binary);
    for(unsigned i=0;i<4096;++i)out.put(char(0x11));
    for(unsigned i=0;i<16;++i)out.put(char(0x22));
  });
  MountScratch(fixture);
  fixture.RunOnGuestThread([](Caller& c) {
    using namespace rex::kernel;
    const u32 h=c.Alloc(4),iosb=c.Alloc(8),a=c.Alloc(4096),b=c.Alloc(4096),list=c.Alloc(8);
    REQUIRE(c.Kernel("NtCreateFile",{h,kReadWriteAccess,c.AllocAttributes("scratch:\\scatter.bin"),
         iosb,0,0,3,1,0x20})==0);
    const u32 handle=c.Load32(h);
    REQUIRE(c.Kernel("NtReadFile",{handle,0,0,0,iosb,a,4,c.AllocQuad(8)})==0);
    c.Store32(list,a);c.Store32(list+4,b);c.Store32(b+16,0xCAFEBABE);
    REQUIRE(c.Kernel("NtReadFileScatter",{handle,0,0,0,iosb,list,8192,c.AllocQuad(0)})==0);
    CHECK(c.Load32(iosb+4)==4112);
    CHECK(c.Load32(a)==0x11111111);
    CHECK(c.Load32(a+4092)==0x11111111);
    CHECK(c.Load32(b)==0x22222222);
    CHECK(c.Load32(b+12)==0x22222222);
    CHECK(c.Load32(b+16)==0xCAFEBABE);
    const u32 pos=c.Alloc(8);
    REQUIRE(c.Kernel("NtQueryInformationFile",{handle,iosb,pos,8,14})==0);
    CHECK(c.Load32(pos+4)==4112);
    CHECK(c.Kernel("NtReadFileScatter",{handle,0,0,0,iosb,0xfffffffc,8192,c.AllocQuad(0)})==X_STATUS_ACCESS_VIOLATION);
    REQUIRE(c.Kernel("NtQueryInformationFile",{handle,iosb,pos,8,14})==0);
    CHECK(c.Load32(pos+4)==4112);
    CHECK(c.Kernel("NtClose",{handle})==0);
  });
}

#include <rex/kernel/object/file_object.h>
#include <rex/kernel/object/object_table.h>
REX_TEST_CASE("metro_io_runtime: original six-argument file open keeps r7 share separate from r8 flags",
              "[kernel][files][metro_io_runtime]") {
  KernelFixture fixture([](const std::filesystem::path& root) {
    WriteScratch(root,"font.xtt",64);
    std::filesystem::create_directories(root/"scratch"/"folder");
  });
  MountScratch(fixture);
  fixture.RunOnGuestThread([](Caller& c) {
    using namespace rex::kernel;
    auto& table=c.GetRuntime().GetObjectTable();
    const u32 h=c.Alloc(4),iosb=c.Alloc(8),data=c.Alloc(4);
    // Exact r4/r7/r8 values from original 922186D0.
    for(u32 share:{0u,1u,3u}) {
      REQUIRE(c.Kernel("NtOpenFile",{h,0x80100000,c.AllocAttributes("scratch:\\font.xtt"),
                                    iosb,share,0x60})==0);
      const u32 handle=c.Load32(h);
      auto file=table.Get<FileObject>(handle);
      REQUIRE(file);
      CHECK(file->is_synchronous);
      REQUIRE(c.Kernel("NtReadFile",{handle,0,0,0,iosb,data,4,0})==0);
      CHECK(c.Load32(iosb+4)==4);
      REQUIRE(c.Kernel("NtClose",{handle})==0);
    }
    // The last argument alone controls synchronous versus asynchronous.
    REQUIRE(c.Kernel("NtOpenFile",{h,0x80100000,c.AllocAttributes("scratch:\\font.xtt"),iosb,1,0x40})==0);
    {
      auto file=table.Get<FileObject>(c.Load32(h));
      REQUIRE(file);
      CHECK_FALSE(file->is_synchronous);
    }
    REQUIRE(c.Kernel("NtClose",{c.Load32(h)})==0);
    CHECK(c.Kernel("NtOpenFile",{h,0x80100000,c.AllocAttributes("scratch:\\folder"),iosb,1,0x60})!=0);
  });
}
