// Exercise the actual XEX loader and guest heap, not a simulated registry.
REX_TEST_CASE("metro: failed image decode releases only its own allocation",
              "[kernel][module][metro_module_lifetime]") {
  KernelFixture fixture(PopulateImages);
  fixture.RunOnGuestThread([](Caller& c) {
    auto& runtime=c.GetRuntime();
    auto* dispatcher=StateOf(runtime).GetFunctionDispatcher();
    auto* heap=StateOf(runtime).GetAddressSpace()->LookupHeap(kImageBase);
    const auto good=BuildImageFile();
    auto bad=good;
    auto parsed=rex::filesystem::XEXImage::Parse(bad);
    REQUIRE(parsed);
    const auto header_bytes=parsed->GetHeaderBytes().size();
    REQUIRE(header_bytes+4<bad.size());
    std::fill_n(bad.begin()+static_cast<std::ptrdiff_t>(header_bytes),4,u8{0});
    auto free_range=[&] {
      rex::kernel::HeapAllocation info{};
      REQUIRE(heap->QueryRegionInfo(kImageBase,&info));
      return info.state==0;
    };
    REQUIRE(free_range());
    rex::kernel::XEXModule candidate(dispatcher,runtime);
    for (unsigned attempt=0;attempt<8;++attempt) {
      CHECK_FALSE(candidate.Load("bad","game:\\bad.xex",bad.data(),bad.size()));
      CHECK_FALSE(candidate.IsLoaded());
      CHECK(candidate.GetBaseAddress()==0);
      CHECK(free_range());
    }
    REQUIRE(candidate.Load("good","game:\\good.xex",good.data(),good.size()));
    REQUIRE(candidate.LoadContinue());
    CHECK(candidate.LoadContinue());
    CHECK_FALSE(free_range());
    {
      rex::kernel::XEXModule collision(dispatcher,runtime);
      CHECK_FALSE(collision.Load("bad","game:\\bad.xex",bad.data(),bad.size()));
      CHECK_FALSE(collision.IsLoaded());
      CHECK_FALSE(free_range());
    }
    CHECK_FALSE(free_range());
    auto* image=StateOf(runtime).GetAddressSpace()->TranslateVirtual(kImageBase);
    CHECK(image[kMarkerOffset]==0xCD);
    REQUIRE(candidate.Unload());
    CHECK(free_range());
    REQUIRE(candidate.Unload());
    REQUIRE(candidate.Load("good","game:\\good.xex",good.data(),good.size()));
    REQUIRE(candidate.LoadContinue());
    REQUIRE(candidate.Unload());
    CHECK(free_range());
  });
}

REX_TEST_CASE("metro: direct XEX destruction and invalid PE roll back guest ranges",
              "[kernel][module][metro_module_lifetime]") {
  KernelFixture fixture;
  fixture.RunOnGuestThread([](Caller& c) {
    auto& runtime=c.GetRuntime();
    auto* dispatcher=StateOf(runtime).GetFunctionDispatcher();
    auto* heap=StateOf(runtime).GetAddressSpace()->LookupHeap(kImageBase);
    auto free_range=[&] {
      rex::kernel::HeapAllocation info{};
      REQUIRE(heap->QueryRegionInfo(kImageBase,&info));
      return info.state==0;
    };
    const auto good=BuildImageFile();
    {
      rex::kernel::XEXModule pending(dispatcher,runtime);
      REQUIRE(pending.Load("good","game:\\good.xex",good.data(),good.size()));
      CHECK_FALSE(free_range());
    }
    CHECK(free_range());
    rex::test::XEXSpec spec;
    spec.load_address=kImageBase;
    spec.page_size_4kb=false;
    spec.image=BuildPEImage();
    auto* dos=reinterpret_cast<IMAGE_DOS_HEADER*>(spec.image.data());
    dos->e_lfanew=static_cast<decltype(dos->e_lfanew)>(spec.image.size()+0x1000);
    const auto malformed=rex::test::BuildXEX(spec);
    rex::kernel::XEXModule candidate(dispatcher,runtime);
    REQUIRE(candidate.Load("malformed","game:\\badpe.xex",malformed.data(),malformed.size()));
    CHECK_FALSE(candidate.LoadContinue());
    CHECK_FALSE(candidate.IsLoaded());
    CHECK(free_range());
    CHECK_FALSE(candidate.LoadContinue());
    REQUIRE(candidate.Load("good","game:\\good.xex",good.data(),good.size()));
    REQUIRE(candidate.LoadContinue());
    REQUIRE(candidate.Unload());
    CHECK(free_range());
  });
}

REX_TEST_CASE("metro: short module input fails before the magic read",
              "[kernel][module][metro_module_lifetime]") {
  KernelFixture fixture;
  fixture.RunOnGuestThread([](Caller& c) {
    auto& runtime=c.GetRuntime();
    const auto handle=rex::kernel::ModuleObject::CreateUserModule(runtime);
    REQUIRE(handle);
    {
      auto module=runtime.GetObjectTable().Get<rex::kernel::ModuleObject>(handle);
      REQUIRE(module);
      const std::array<u8,3> short_input{'X','E','X'};
      CHECK(module->LoadFromMemory(runtime,nullptr,0)==rex::kernel::X_STATUS_INVALID_PARAMETER);
      CHECK(module->LoadFromMemory(runtime,short_input.data(),short_input.size())==
            rex::kernel::X_STATUS_INVALID_PARAMETER);
      CHECK_FALSE(module->GetXEX());
    }
    rex::kernel::CloseOwned(runtime.GetObjectTable(),handle);
  });
}
