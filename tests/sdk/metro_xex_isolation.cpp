// Reproduce the retail XAM table overlapping the dashboard through the
// formerly aliased backing views, without loading proprietary executables.
REX_TEST_CASE("metro_xex_isolation: dispatch tables cannot corrupt another XEX heap",
              "[kernel][dispatcher][metro_xex_isolation]") {
  auto& memory = GetTestMemory();
  rex::kernel::FunctionDispatcher dispatcher(&memory);
  constexpr u32 image=0x815f0000, code=0x81670000, size=0x610000;
  constexpr u32 dash=0x92000000;
  auto* heap=memory.LookupHeap(dash);
  REQUIRE(heap);
  REQUIRE(heap->AllocFixed(dash,0x1000,0x1000,
      rex::kernel::kMemoryAllocationReserve|rex::kernel::kMemoryAllocationCommit,
      rex::kernel::kMemoryProtectRead|rex::kernel::kMemoryProtectWrite));
  auto* slot=memory.TranslateVirtual<rex::be_u32*>(dash+0x4d0);
  slot[0]=0x25a;
  slot[1]=0x269;
  REQUIRE(dispatcher.InitializeFunctionTable(code,0x406a88,image,size));
  CHECK(static_cast<u32>(slot[0])==0x25a);
  CHECK(static_cast<u32>(slot[1])==0x269);
  constexpr u32 target=code+(0x820004d0-(image+size))/2;
  REQUIRE(dispatcher.SetFunction(target,&DummyFn));
  auto* native=memory.TranslateVirtual<PPCFunc**>(0x820004d0);
  CHECK(*native==&DummyFn);
  CHECK(static_cast<u32>(slot[0])==0x25a);
  CHECK(static_cast<u32>(slot[1])==0x269);
  slot[0]=0x9293a22c;
  slot[1]=0x9293a23c;
  CHECK(*native==&DummyFn);
  REQUIRE(memory.DestroyFunctionTable(code));
  heap->Release(dash);
}
