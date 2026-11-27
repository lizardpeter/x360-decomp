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


namespace {
constexpr u32 kProfileOverlayBase=0x90100000u;
constexpr u32 kSigninCode=0x90105000u;
constexpr u32 kGamerCode=0x90106000u;
constexpr u32 kCreateCode=0x90103000u;
constexpr u32 kSigninEntry=0x901054E0u;
constexpr u32 kGamerEntry=0x9011C6C0u;
constexpr u32 kCreateEntry=0x901094A8u;
constexpr u32 kSharedCode=0x90107000u;
void MetroSigninDummy(PPCContext&,u8*) {}
void MetroGamerDummy(PPCContext&,u8*) {}
void MetroCreateDummy(PPCContext&,u8*) {}
void RegisterSigninOverlay(rex::kernel::IFunctionRegistrar* r) {
  r->SetFunction(kSigninEntry,&MetroSigninDummy);
  r->SetFunction(kSharedCode,&MetroSigninDummy);
}
void RegisterGamerOverlay(rex::kernel::IFunctionRegistrar* r) {
  r->SetFunction(kGamerEntry,&MetroGamerDummy);
  r->SetFunction(kSharedCode,&MetroGamerDummy);
}
void RegisterCreateOverlay(rex::kernel::IFunctionRegistrar* r) {
  r->SetFunction(kCreateEntry,&MetroCreateDummy);
  r->SetFunction(kSharedCode,&MetroCreateDummy);
}
}

REX_TEST_CASE("metro_xex_isolation: original profile overlay ranges unload and register independently",
              "[kernel][dispatcher][metro_xex_isolation]") {
  auto& memory=GetTestMemory();
  rex::kernel::FunctionDispatcher dispatcher(&memory);
  // Original image and executable section extents from decoded 17559 metadata.
  // Synthetic callbacks test the real SDK memory/dispatcher contract only.
  struct Overlay {
    const char* name;
    u32 code,size,image_size,entry;
    PPCFunc* fn;
    rex::kernel::FunctionDispatcher::RegisterFn reg;
  };
  const Overlay modules[]={
      {"signin",kSigninCode,103420u,274432u,kSigninEntry,&MetroSigninDummy,&RegisterSigninOverlay},
      {"gamerprofile",kGamerCode,133728u,319488u,kGamerEntry,&MetroGamerDummy,&RegisterGamerOverlay},
      {"createprofile",kCreateCode,40236u,114688u,kCreateEntry,&MetroCreateDummy,&RegisterCreateOverlay},
  };
  // Keep an unrelated native module mapped across all overlay transitions.
  constexpr u32 other=0x916D2000u,other_base=0x916D0000u;
  REQUIRE(dispatcher.InitializeFunctionTable(other,25356u,other_base,94208u));
  REQUIRE(dispatcher.SetFunction(other+4,&DummyFn));
  for (unsigned cycle=0;cycle<2;++cycle) {
    for (const auto& mod:modules) {
      REQUIRE(dispatcher.InitializeFunctionTable(mod.code,mod.size,kProfileOverlayBase,mod.image_size));
      dispatcher.RegisterModule(mod.name,mod.code,mod.reg);
      REQUIRE(dispatcher.GetFunction(mod.entry)==mod.fn);
      REQUIRE(dispatcher.GetFunction(kSharedCode)==mod.fn);
      auto* slot=memory.TranslateVirtual<PPCFunc**>(
          kProfileOverlayBase+mod.image_size+(kSharedCode-mod.code)*2);
      CHECK(*slot==mod.fn);
      const auto thunk=dispatcher.AllocateThunk(mod.fn,mod.entry);
      REQUIRE(thunk!=0);
      CHECK(dispatcher.GetFunction(thunk)==mod.fn);
      CHECK(dispatcher.GetFunction(other+4)==&DummyFn);
      // The next overlay must not replace a still-live module's table.
      const auto& next=modules[(&mod-modules+1)%3];
      CHECK_FALSE(dispatcher.InitializeFunctionTable(next.code,next.size,kProfileOverlayBase,next.image_size));
      CHECK(dispatcher.GetFunction(kSharedCode)==mod.fn);
      auto cleared=dispatcher.UnregisterModule(mod.name);
      REQUIRE(cleared.has_value());
      CHECK(cleared->first==mod.code+mod.size);
      CHECK(cleared->second==thunk+4);
      CHECK(dispatcher.GetFunction(mod.entry)==nullptr);
      CHECK(dispatcher.GetFunction(kSharedCode)==nullptr);
      CHECK(dispatcher.GetFunction(thunk)==nullptr);
      CHECK(dispatcher.GetFunction(other+4)==&DummyFn);
    }
  }
  REQUIRE(memory.DestroyFunctionTable(other));
}
