#include "gpu/xenos/geometry_cull.h"
#include "gpu/xenos/command_processor.h"
#include "gpu/xenos/pipeline/shader/shader.h"
#include <rex/memory/stream.h>

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


REX_TEST_CASE("metro_gpu_ring: full linear command span is distinguishable from empty",
              "[gpu][metro_gpu_ring]") {
  std::array<rex::u8,8> bytes{0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
  rex::memory::RingBuffer reader(bytes.data(),bytes.size());
  CHECK(reader.IsEmpty());
  reader.SetFullReadRange();
  CHECK_FALSE(reader.IsEmpty());
  CHECK(reader.GetReadCount()==8);
  CHECK(reader.GetWriteCount()==0);
  CHECK(reader.ReadAndSwap<rex::u32>()==0x12345678u);
  CHECK(reader.GetReadCount()==4);
  CHECK(reader.ReadAndSwap<rex::u32>()==0x9abcdef0u);
  CHECK(reader.IsEmpty());
  CHECK(reader.GetReadCount()==0);
  reader.SetFullReadRange();
  reader.AdvanceRead(8);
  CHECK(reader.IsEmpty());
  reader.SetFullReadRange();
  auto range=reader.BeginRead(8);
  reader.EndRead(range);
  CHECK(reader.IsEmpty());
}


REX_TEST_CASE("metro_gpu_ring: geometry cull input layout matches vertex output",
              "[gpu][metro_gpu_ring]") {
  for(unsigned planes=0;planes<=6;++planes)
    for(bool cull:{false,true})
      for(bool kill:{false,true}) {
        const unsigned expected=(cull?planes:0)+(kill?1:0);
        CHECK(rex::gpu::GeometryInputCullDistanceCount(cull,planes,kill)==expected);
      }
}
REX_TEST_CASE("metro_gpu_ring: cull any wholly negative plane rather than all planes",
              "[gpu][metro_gpu_ring]") {
  // Exhaust every negative/nonnegative combination across up to three
  // planes and four vertices, including the skip for recalculated point UCP.
  for(unsigned vertices:{1u,3u,4u})
    for(unsigned planes=1;planes<=3;++planes)
      for(unsigned first=0;first<planes;++first) {
        bool correct=true;
        const unsigned vertex_mask=(1u<<vertices)-1u;
        for(unsigned mask=0;mask<(1u<<(vertices*planes));++mask) {
          bool want=false;
          for(unsigned p=first;p<planes;++p)
            want|=((mask>>(p*vertices))&vertex_mask)==vertex_mask;
          bool got=rex::gpu::GeometryAnyCullPlane(first,planes,vertices,
              [&](unsigned p,unsigned v){return bool(mask&(1u<<(p*vertices+v)));},
              [](bool a,bool b){return a&&b;},[](bool a,bool b){return a||b;});
          if(got!=want){correct=false;break;}
        }
        INFO("vertices "<<vertices<<" planes "<<planes<<" skip "<<first);
        CHECK(correct);
      }
}


REX_TEST_CASE_METHOD(Fixture,"metro_gpu_ring: immediate shader upload crosses the ring boundary",
                     "[gpu][metro_gpu_ring]") {
  auto& memory=rex::test::GetTestMemory();
  rex::test::FakeTitleContext title(memory);
  rex::test::FakeDriverContext context;
  rex::gpu::null::NullXenosGraphicsDriver driver;
  REQUIRE(driver.Initialize(context));
  REQUIRE(driver.AttachTitle(rex::TitleInfo{},title,title,title));
  const auto allocation=memory.SystemHeapAlloc(0x6000,0x1000,rex::kernel::kSystemHeapPhysical);
  REQUIRE(allocation);
  const auto ring=memory.GetPhysicalAddress(allocation), wb=ring+0x2000;
  auto wait_for=[&](rex::u32 value) {
    const auto end=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    while(GetBig(memory,wb)!=value && std::chrono::steady_clock::now()<end)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    return GetBig(memory,wb)==value;
  };
  // 4 KiB ring. First move the reader near its end using a single NOP.
  driver.InitializeRingBuffer(ring,9);
  driver.EnableReadPointerWriteBack(wb,6);
  Put(memory,ring,rex::xenos::BuildPacketType3(rex::xenos::PM4_NOP,1019));
  driver.WriteRegister(kWritePointerRegister,1020);
  REQUIRE(wait_for(1020));
  Put(memory,ring+1020*4,rex::xenos::BuildPacketType3(rex::xenos::PM4_IM_LOAD_IMMEDIATE,5));
  Put(memory,ring+1021*4,static_cast<rex::u32>(rex::xenos::ShaderType::kVertex));
  Put(memory,ring+1022*4,3);
  Put(memory,ring+1023*4,0x11223344u);
  Put(memory,ring,0x55667788u);
  Put(memory,ring+4,0x99aabbccu);
  // Distinct bytes immediately after the ring must not be used as ucode.
  Put(memory,ring+0x1000,0xdeadbeefu);
  Put(memory,ring+0x1004,0xcafebabeu);
  driver.WriteRegister(kWritePointerRegister,2);
  REQUIRE(wait_for(2));
  auto* processor=driver.GetCommandProcessor();
  std::vector<rex::u32> words;
  processor->CallInThreadAndWait([&]{
    if(auto* shader=processor->GetActiveVertexShader()) words=shader->GetUcodeData();
  });
  CHECK((words==std::vector<rex::u32>{0x11223344u,0x55667788u,0x99aabbccu}));
  driver.DetachTitle();
  driver.Shutdown();
}

REX_TEST_CASE_METHOD(Fixture,"metro_gpu_ring: short fixed packet cannot consume its successor",
                     "[gpu][metro_gpu_ring]") {
  auto& memory=rex::test::GetTestMemory();
  rex::test::FakeTitleContext title(memory);
  rex::test::FakeDriverContext context;
  rex::gpu::null::NullXenosGraphicsDriver driver;
  REQUIRE(driver.Initialize(context));
  REQUIRE(driver.AttachTitle(rex::TitleInfo{},title,title,title));
  const auto allocation=memory.SystemHeapAlloc(0x6000,0x1000,rex::kernel::kSystemHeapPhysical);
  REQUIRE(allocation);
  const auto ring=memory.GetPhysicalAddress(allocation), wb=ring+0x2000;
  const auto marker=wb+4, forbidden=wb+8;
  auto wait_for=[&](rex::u32 address,rex::u32 value) {
    const auto end=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    while(GetBig(memory,address)!=value && std::chrono::steady_clock::now()<end)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    return GetBig(memory,address)==value;
  };
  for(auto opcode:{rex::xenos::PM4_REG_RMW,rex::xenos::PM4_WAIT_REG_MEM,
                   rex::xenos::PM4_COND_WRITE,rex::xenos::PM4_IM_LOAD_IMMEDIATE}) {
    Put(memory,marker,0);Put(memory,forbidden,0);
    Put(memory,ring,rex::xenos::BuildPacketType3(rex::xenos::PM4_MEM_WRITE,2));
    Put(memory,ring+4,marker|2u);Put(memory,ring+8,0x12345678u);
    Put(memory,ring+12,rex::xenos::BuildPacketType3(opcode,1));
    Put(memory,ring+16,0x7u);
    Put(memory,ring+20,rex::xenos::BuildPacketType3(rex::xenos::PM4_MEM_WRITE,2));
    Put(memory,ring+24,forbidden|2u);Put(memory,ring+28,0xdeadbeefu);
    driver.InitializeRingBuffer(ring,9);
    driver.EnableReadPointerWriteBack(wb,6);
    driver.WriteRegister(kWritePointerRegister,8);
    REQUIRE(wait_for(marker,0x12345678u));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    CHECK(GetBig(memory,forbidden)==0);
    CHECK(GetBig(memory,wb)==0);
  }
  driver.DetachTitle();
  driver.Shutdown();
}

#include "gpu/xenos/shared_memory.h"

namespace {
class MetroTestSharedMemory final : public rex::gpu::SharedMemory {
 public:
  explicit MetroTestSharedMemory(rex::test::FakeTitleContext& title)
      :SharedMemory(title,title) { InitializeCommon(); }
  rex::u32 PageBytes() const { return rex::u32{1}<<GetPageSizeLog2(); }
  std::vector<std::pair<rex::u32,rex::u32>> uploads;
  bool fail_upload=false;
 protected:
  bool UploadRanges(const std::vector<std::pair<rex::u32,rex::u32>>& ranges) override {
    uploads=ranges;
    if (fail_upload) return false;
    for (const auto& [first,count]:ranges)
      MarkRangeValid(first*PageBytes(),count*PageBytes(),false);
    return true;
  }
};
}

REX_TEST_CASE_METHOD(Fixture,"metro_gpu_ring: unchanged vertex fetch must revalidate CPU-written pages",
                     "[gpu][metro_gpu_ring]") {
  auto& memory=rex::test::GetTestMemory();
  rex::test::FakeTitleContext title(memory);
  MetroTestSharedMemory shared(title);
  const rex::u32 page=shared.PageBytes();
  const rex::u32 start=63*page+page-8;
  CHECK_FALSE(shared.IsRangeValid(start,16));
  REQUIRE(shared.RequestRange(start,16));
  CHECK(shared.IsRangeValid(start,16));
  CHECK(shared.IsRangeValid(start,8));
  CHECK(shared.IsRangeValid(start+8,8));
  {
    auto lock=shared.AcquireLock();
    shared.OnPhysicalWrite({start+8,1},true);
  }
  CHECK(shared.IsRangeValid(start,8));
  CHECK_FALSE(shared.IsRangeValid(start+8,8));
  CHECK_FALSE(shared.IsRangeValid(start,16));
  shared.fail_upload=true;
  CHECK_FALSE(shared.RequestRange(start,16));
  CHECK_FALSE(shared.IsRangeValid(start,16));
  shared.fail_upload=false;
  REQUIRE(shared.RequestRange(start,16));
  CHECK(shared.IsRangeValid(start,16));
  shared.RangeWrittenByGPU(start,16);
  CHECK(shared.IsRangeValid(start,16));
  shared.InvalidateAllPages();
  CHECK_FALSE(shared.IsRangeValid(start,16));
  CHECK(shared.IsRangeValid(0,0));
  CHECK_FALSE(shared.IsRangeValid(shared.kBufferSize-1,2));
  CHECK_FALSE(shared.IsRangeValid(0xffffffffu,16));
}

REX_TEST_CASE_METHOD(Fixture,"metro_gpu_ring: disjoint byte requests merge into unique sorted page uploads",
                     "[gpu][metro_gpu_ring]") {
  auto& memory=rex::test::GetTestMemory();
  rex::test::FakeTitleContext title(memory);
  MetroTestSharedMemory shared(title);
  const rex::u32 page=shared.PageBytes();
  const std::pair<rex::u32,rex::u32> ranges[]={
    {3*page+8,4},{page+4,4},{page+32,4},{2*page-2,4},
    {3*page+32,8},{5*page+1,1}};
  REQUIRE(shared.RequestRanges(ranges,std::size(ranges)));
  CHECK((shared.uploads==std::vector<std::pair<rex::u32,rex::u32>>{{1,3},{5,1}}));
  CHECK(shared.IsRangeValid(page,3*page));
  CHECK_FALSE(shared.IsRangeValid(4*page,1));
  CHECK(shared.IsRangeValid(5*page,1));
  shared.uploads.clear();
  REQUIRE(shared.RequestRanges(ranges,std::size(ranges)));
  CHECK(shared.uploads.empty());
  REQUIRE(shared.RequestRange(shared.kBufferSize-1,1));
  CHECK(shared.IsRangeValid(shared.kBufferSize-1,1));
}
