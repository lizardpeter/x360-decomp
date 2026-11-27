
// Execute actual guest callbacks using both ABI modes; no original bytes.
namespace {
std::atomic<rex::u32> metro_audio_received{0};
std::atomic<rex::u32> metro_audio_field{0};
std::atomic<bool> metro_audio_direct{false};
std::atomic<rex::u32> metro_audio_output_address{0},metro_audio_output_seen{0};
void MetroAudioContextCallback(PPCContext& ctx, rex::u8* base) {
  const auto address=ctx.r3.u32;
  const auto offset=metro_audio_direct.load()?304u:0u;
  const auto* field=reinterpret_cast<const rex::be_u32*>(base+address+offset);
  metro_audio_field.store(static_cast<rex::u32>(*field));
  const auto output=metro_audio_output_address.load();
  if (output) metro_audio_output_seen.store(static_cast<rex::u32>(*reinterpret_cast<const rex::be_u32*>(base+output)));
  metro_audio_received.store(address);
}
}
REX_TEST_CASE("metro_audio_context: original direct context is not wrapped",
              "[kernel][metro_audio_context]") {
  rex::test::KernelFixture fixture;
  auto& runtime=fixture.GetRuntime();
  auto* memory=StateOf(runtime).GetAddressSpace();
  const auto object=memory->SystemHeapAlloc(512);
  REQUIRE(object);
  *memory->TranslateVirtual<rex::be_u32*>(object+304)=0x12345678u;
  const auto cb=StateOf(runtime).GetFunctionDispatcher()->AllocateThunk(&MetroAudioContextCallback,0);
  REQUIRE(cb);
  rex::kernel::APU apu(runtime,&fixture.GetAudio());
  REQUIRE(apu.Setup());
  metro_audio_direct=true;
  metro_audio_received=0;
  metro_audio_field=0;
  const auto output=object+400;
  *memory->TranslateVirtual<rex::be_u32*>(output)=0;
  metro_audio_output_address=output;
  metro_audio_output_seen=0;
  const auto direct=apu.RegisterClient(cb,object,true,output);
  REQUIRE(direct);
  REQUIRE(WaitFor([]{return metro_audio_received.load()!=0;}));
  CHECK(metro_audio_received.load()==object);
  CHECK(metro_audio_field.load()==0x12345678u);
  CHECK(metro_audio_output_seen.load()==(0x41550000u|*direct));
  // Stop and join before changing callback inspection mode.
  apu.Shutdown();
  CHECK(static_cast<rex::u32>(*memory->TranslateVirtual<rex::be_u32*>(object+304))==0x12345678u);
  rex::kernel::APU legacy(runtime,&fixture.GetAudio());
  REQUIRE(legacy.Setup());
  metro_audio_direct=false;
  metro_audio_output_address=0;
  metro_audio_received=0;
  metro_audio_field=0;
  const auto wrapped=legacy.RegisterClient(cb,object);
  REQUIRE(wrapped);
  REQUIRE(WaitFor([]{return metro_audio_received.load()!=0;}));
  CHECK(metro_audio_received.load()!=object);
  CHECK(metro_audio_field.load()==object);
  legacy.Shutdown();
  memory->SystemHeapFree(object);
}


REX_TEST_CASE("metro_audio_context: verify loaded original module layout",
              "[kernel][metro_audio_context]") {
  using rex::kernel::GetRetailRenderContext;
  using rex::kernel::RetailRenderContext;
  CHECK(GetRetailRenderContext(0x819A5878u,0x815f0000u,0x610000u,0x81696af0u)==RetailRenderContext::kXam17559);
  CHECK(GetRetailRenderContext(0x9804BEA0u,0x98000000u,638976u,0)==RetailRenderContext::kBootanim17559);
  CHECK(GetRetailRenderContext(0x819A5878u,0x98000000u,638976u,0)==RetailRenderContext::kNone);
  CHECK(GetRetailRenderContext(0x9804BEA0u,0x815f0000u,0x610000u,0x81696af0u)==RetailRenderContext::kNone);
  CHECK(GetRetailRenderContext(0x9804BEA0u,0x98000000u,638972u,0)==RetailRenderContext::kNone);
  CHECK(GetRetailRenderContext(0x9804BEA0u,0x98000000u,638976u,0x98020E60u)==RetailRenderContext::kNone);
}

namespace {
std::atomic<bool> metro_audio_blocked{false},metro_audio_release{false},metro_audio_finished{false};
std::atomic<rex::u32> metro_audio_retained_word{0};
void MetroAudioRetiringCallback(PPCContext& ctx,rex::u8* base) {
  const auto argument=ctx.r3.u32;
  metro_audio_blocked.store(true,std::memory_order_release);
  // Bounded even if a test assertion fails.
  const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
  while (!metro_audio_release.load(std::memory_order_acquire) &&
         std::chrono::steady_clock::now()<deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  metro_audio_retained_word.store(static_cast<rex::u32>(
      *reinterpret_cast<const rex::be_u32*>(base+argument)));
  metro_audio_finished.store(true,std::memory_order_release);
}
}
REX_TEST_CASE("metro_audio_context: retiring slot survives an in-flight legacy callback",
              "[kernel][metro_audio_context]") {
  rex::test::KernelFixture fixture;
  auto& runtime=fixture.GetRuntime();
  rex::kernel::APU apu(runtime,&fixture.GetAudio());
  metro_audio_blocked=false;metro_audio_release=false;
  metro_audio_finished=false;metro_audio_retained_word=0;
  const auto cb=StateOf(runtime).GetFunctionDispatcher()->AllocateThunk(&MetroAudioRetiringCallback,0);
  REQUIRE(cb);
  REQUIRE(apu.Setup());
  const auto first=apu.RegisterClient(cb,0x12345678u);
  REQUIRE(first);
  const auto started=WaitFor([]{return metro_audio_blocked.load(std::memory_order_acquire);});
  if (!started)metro_audio_release=true;
  REQUIRE(started);
  apu.UnregisterClient(*first);
  const auto next=apu.RegisterClient(0,0x87654321u);
  // Always release before an assertion might unwind this fixture.
  metro_audio_release.store(true,std::memory_order_release);
  REQUIRE(next);
  CHECK(*next!=*first);
  REQUIRE(WaitFor([]{return metro_audio_finished.load(std::memory_order_acquire);}));
  CHECK(metro_audio_retained_word.load()==0x12345678u);
  // Reserve all other slots until the callback releases its own index.
  std::vector<rex::u32> reserved{*next};
  for (unsigned i=0;i<rex::kernel::APU::kMaxClients-2;++i) {
    auto r=apu.RegisterClient(0,0);
    REQUIRE(r);
    reserved.push_back(*r);
  }
  std::optional<rex::u32> reclaimed;
  REQUIRE(WaitFor([&]{
    auto r=apu.RegisterClient(0,0);
    if (!r)return false;
    reclaimed=*r;return true;
  }));
  CHECK(reclaimed.has_value());
  CHECK(fixture.GetAudio().GetStats().open_streams==rex::kernel::APU::kMaxClients);
  apu.Shutdown();
}
