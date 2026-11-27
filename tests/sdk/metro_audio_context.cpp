
// Execute actual guest callbacks using both ABI modes; no original bytes.
namespace {
std::atomic<rex::u32> metro_audio_received{0};
std::atomic<rex::u32> metro_audio_field{0};
std::atomic<bool> metro_audio_direct{false};
void MetroAudioContextCallback(PPCContext& ctx, rex::u8* base) {
  const auto address=ctx.r3.u32;
  const auto offset=metro_audio_direct.load()?304u:0u;
  const auto* field=reinterpret_cast<const rex::be_u32*>(base+address+offset);
  metro_audio_field.store(static_cast<rex::u32>(*field));
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
  const auto direct=apu.RegisterClient(cb,object,true);
  REQUIRE(direct);
  REQUIRE(WaitFor([]{return metro_audio_received.load()!=0;}));
  CHECK(metro_audio_received.load()==object);
  CHECK(metro_audio_field.load()==0x12345678u);
  // Stop and join before changing callback inspection mode.
  apu.Shutdown();
  CHECK(static_cast<rex::u32>(*memory->TranslateVirtual<rex::be_u32*>(object+304))==0x12345678u);
  rex::kernel::APU legacy(runtime,&fixture.GetAudio());
  REQUIRE(legacy.Setup());
  metro_audio_direct=false;
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

REX_TEST_CASE("metro_audio_context: only proven paired registrations select direct ABI",
              "[kernel][metro_audio_context]") {
  using rex::kernel::GetRetailRenderContext;
  using rex::kernel::RetailRenderContext;
  CHECK(GetRetailRenderContext(0x819A5878u,0x819AC5A0u)==RetailRenderContext::kXam17559);
  CHECK(GetRetailRenderContext(0x9804BEA0u,0x980517C8u)==RetailRenderContext::kBootanim17559);
  CHECK(GetRetailRenderContext(0x819A5878u,0x980517C8u)==RetailRenderContext::kNone);
  CHECK(GetRetailRenderContext(0x9804BEA0u,0x819AC5A0u)==RetailRenderContext::kNone);
  CHECK(GetRetailRenderContext(0x819A5878u,0)==RetailRenderContext::kNone);
  CHECK(GetRetailRenderContext(0,0x980517C8u)==RetailRenderContext::kNone);
}
