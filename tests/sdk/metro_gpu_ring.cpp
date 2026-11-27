
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
