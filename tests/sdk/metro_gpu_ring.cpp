
// Both rings execute actual guest PM4 on the SDK worker. No guest firmware.
REX_TEST_CASE_METHOD(Fixture,"metro_gpu_ring: reinitialization does not consume prior ring's WPTR",
                     "[gpu][metro_gpu_ring]") {
  auto& memory=rex::test::GetTestMemory();
  rex::test::FakeTitleContext title(memory);
  rex::test::FakeDriverContext context;
  rex::gpu::null::NullXenosGraphicsDriver driver;
  REQUIRE(driver.Initialize(context));
  REQUIRE(driver.AttachTitle(rex::TitleInfo{},title,title,title));
  const auto allocation=memory.SystemHeapAlloc(0x6000,0x1000,rex::kernel::kSystemHeapPhysical);
  REQUIRE(allocation);
  const auto first=memory.GetPhysicalAddress(allocation);
  const auto second=first+0x1000;
  const auto old_wb=first+0x2000;
  const auto new_wb=old_wb+4;
  const auto scratch=old_wb+0x40;
  auto packet=[&](rex::u32 address,rex::u32 value) {
    Put(memory,address,rex::xenos::BuildPacketType3(rex::xenos::PM4_MEM_WRITE,2));
    Put(memory,address+4,scratch|2u);
    Put(memory,address+8,value);
  };
  auto wait_for=[&](rex::u32 address,rex::u32 value) {
    const auto end=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    while(GetBig(memory,address)!=value && std::chrono::steady_clock::now()<end)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    return GetBig(memory,address)==value;
  };
  packet(first,0x11223344u);
  packet(second,0x55667788u);
  Put(memory,old_wb,0xffffffffu);Put(memory,new_wb,0xffffffffu);
  Put(memory,scratch,0);
  driver.InitializeRingBuffer(first,9);
  driver.EnableReadPointerWriteBack(old_wb,6);
  driver.WriteRegister(kWritePointerRegister,3);
  REQUIRE(wait_for(old_wb,3));
  const auto old_scratch=GetBig(memory,scratch);
  REQUIRE(old_scratch!=0);
  driver.InitializeRingBuffer(second,9);
  driver.EnableReadPointerWriteBack(new_wb,6);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  CHECK(GetBig(memory,old_wb)==3);
  CHECK(GetBig(memory,new_wb)==0);
  CHECK(GetBig(memory,scratch)==old_scratch);
  driver.WriteRegister(kWritePointerRegister,3);
  REQUIRE(wait_for(new_wb,3));
  CHECK(GetBig(memory,scratch)!=old_scratch);
  // A reused allocation is still a new ring generation.
  const auto second_scratch=GetBig(memory,scratch);
  packet(second,0xAABBCCDDu);
  driver.InitializeRingBuffer(second,9);
  driver.EnableReadPointerWriteBack(new_wb,6);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  CHECK(GetBig(memory,new_wb)==0);
  CHECK(GetBig(memory,scratch)==second_scratch);
  driver.WriteRegister(kWritePointerRegister,3);
  REQUIRE(wait_for(new_wb,3));
  CHECK(GetBig(memory,scratch)!=second_scratch);
  driver.DetachTitle();
  driver.Shutdown();
}

REX_TEST_CASE_METHOD(Fixture,"metro_gpu_ring: stopping an indirect wait cancels without completing its commands",
                     "[gpu][metro_gpu_ring]") {
  auto& memory=rex::test::GetTestMemory();
  rex::test::FakeTitleContext title(memory);
  rex::test::FakeDriverContext context;
  rex::gpu::null::NullXenosGraphicsDriver driver;
  REQUIRE(driver.Initialize(context));
  REQUIRE(driver.AttachTitle(rex::TitleInfo{},title,title,title));
  const auto allocation=memory.SystemHeapAlloc(0x6000,0x1000,rex::kernel::kSystemHeapPhysical);
  REQUIRE(allocation);
  const auto ring=memory.GetPhysicalAddress(allocation);
  const auto indirect=ring+0x1000, wb=ring+0x2000;
  const auto entered=wb+4, condition=wb+8, forbidden=wb+12;
  Put(memory,wb,0);Put(memory,entered,0);Put(memory,condition,0);Put(memory,forbidden,0);
  // Publish a marker, then wait forever on an unsatisfied memory condition.
  Put(memory,indirect,rex::xenos::BuildPacketType3(rex::xenos::PM4_MEM_WRITE,2));
  Put(memory,indirect+4,entered|2u);Put(memory,indirect+8,0x01010101u);
  Put(memory,indirect+12,rex::xenos::BuildPacketType3(rex::xenos::PM4_WAIT_REG_MEM,5));
  Put(memory,indirect+16,0x13u); // memory, equality
  Put(memory,indirect+20,condition|2u);Put(memory,indirect+24,1);
  Put(memory,indirect+28,0xffffffffu);Put(memory,indirect+32,0);
  Put(memory,indirect+36,rex::xenos::BuildPacketType3(rex::xenos::PM4_MEM_WRITE,2));
  Put(memory,indirect+40,forbidden|2u);Put(memory,indirect+44,0x11111111u);
  Put(memory,ring,rex::xenos::BuildPacketType3(rex::xenos::PM4_INDIRECT_BUFFER,2));
  Put(memory,ring+4,indirect);Put(memory,ring+8,12);
  Put(memory,ring+12,rex::xenos::BuildPacketType3(rex::xenos::PM4_MEM_WRITE,2));
  Put(memory,ring+16,forbidden|2u);Put(memory,ring+20,0x22222222u);
  driver.InitializeRingBuffer(ring,9);
  driver.EnableReadPointerWriteBack(wb,6);
  driver.WriteRegister(kWritePointerRegister,6);
  const auto end=std::chrono::steady_clock::now()+std::chrono::seconds(5);
  while(GetBig(memory,entered)==0 && std::chrono::steady_clock::now()<end)
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  const auto reached=GetBig(memory,entered);
  driver.DetachTitle(); // must join the worker even though the wait is unsatisfied
  CHECK(reached!=0);
  CHECK(GetBig(memory,forbidden)==0);
  CHECK(GetBig(memory,wb)==0);
  driver.Shutdown();
}


REX_TEST_CASE_METHOD(Fixture,"metro_gpu_ring: malformed indirect stream cannot complete its parent",
                     "[gpu][metro_gpu_ring]") {
  auto& memory=rex::test::GetTestMemory();
  rex::test::FakeTitleContext title(memory);
  rex::test::FakeDriverContext context;
  rex::gpu::null::NullXenosGraphicsDriver driver;
  REQUIRE(driver.Initialize(context));
  REQUIRE(driver.AttachTitle(rex::TitleInfo{},title,title,title));
  const auto allocation=memory.SystemHeapAlloc(0x6000,0x1000,rex::kernel::kSystemHeapPhysical);
  REQUIRE(allocation);
  const auto ring=memory.GetPhysicalAddress(allocation);
  const auto indirect=ring+0x1000, wb=ring+0x2000;
  const auto marker=wb+4, forbidden=wb+8, recovered=wb+12;
  auto write_packet=[&](rex::u32 address,rex::u32 destination,rex::u32 value) {
    Put(memory,address,rex::xenos::BuildPacketType3(rex::xenos::PM4_MEM_WRITE,2));
    Put(memory,address+4,destination|2u);Put(memory,address+8,value);
  };
  auto wait_for=[&](rex::u32 address,rex::u32 value) {
    const auto end=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    while(GetBig(memory,address)!=value && std::chrono::steady_clock::now()<end)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    return GetBig(memory,address)==value;
  };
  // Both a truncated type 3 and a truncated type 1 must propagate to the
  // parent without consuming the next command or publishing a read index.
  for(unsigned mutation=0;mutation<2;++mutation) {
    Put(memory,marker,0);Put(memory,forbidden,0);Put(memory,recovered,0);
    write_packet(indirect,marker,0x01010101u);
    Put(memory,indirect+12,mutation==0?
        rex::xenos::BuildPacketType3(rex::xenos::PM4_MEM_WRITE,2):0x40000000u);
    // The payload physically exists but is outside the submitted child span.
    Put(memory,indirect+16,forbidden|2u);Put(memory,indirect+20,0x33333333u);
    Put(memory,ring,rex::xenos::BuildPacketType3(rex::xenos::PM4_INDIRECT_BUFFER,2));
    Put(memory,ring+4,indirect);Put(memory,ring+8,4);
    write_packet(ring+12,forbidden,0x22222222u);
    driver.InitializeRingBuffer(ring,9);
    driver.EnableReadPointerWriteBack(wb,6);
    driver.WriteRegister(kWritePointerRegister,6);
    REQUIRE(wait_for(marker,0x01010101u));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    CHECK(GetBig(memory,forbidden)==0);
    CHECK(GetBig(memory,wb)==0);
    // Reprogramming, not a guessed pointer advance, permits recovery.
    driver.InitializeRingBuffer(ring,9);
    write_packet(ring,recovered,0xAABBCCDDu);
    driver.EnableReadPointerWriteBack(wb,6);
    driver.WriteRegister(kWritePointerRegister,3);
    REQUIRE(wait_for(wb,3));
    CHECK(GetBig(memory,recovered)==0xAABBCCDDu);
  }
  driver.DetachTitle();
  driver.Shutdown();
}
