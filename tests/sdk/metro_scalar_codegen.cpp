
// PPC encodings independently assembled for powerpc64-linux-gnu.
// FM=1 selects the least significant FPSCR nibble, FM=128 the highest.
REX_TEST_CASE("metro_scalar_codegen: FPSCR field masks select the correct nibble",
              "[codegen][metro_scalar_codegen]") {
  const auto code=EmitFunction("metro_fpscr_fields",{
    0xFC000D8E,0xFC020D8E,0xFC040D8E,0xFC080D8E,
    0xFC100D8E,0xFC200D8E,0xFC400D8E,0xFC800D8E,
    0xFD000D8E,0xFD020D8E,0xFDFE0D8E,kBlr});
  constexpr const char* masks[]={
    "0x00000000","0x0000000F","0x000000F0","0x00000F00",
    "0x0000F000","0x000F0000","0x00F00000","0x0F000000",
    "0xF0000000","0xF000000F"};
  // Assert the masks in instruction order, not merely their presence.
  size_t pos=0;
  for(const auto* mask:masks) {
    auto at=code.find("ctx.fpscr.StoreToHost(",pos);
    REQUIRE(at!=std::string::npos);
    auto end=code.find(';',at);
    REQUIRE(end!=std::string::npos);
    auto line=code.substr(at,end-at);
    CHECK(line.find(std::string("& ")+mask)!=std::string::npos);
    // The exact field mask occurs after the source FPR, not on the
    // complement applied to the previous FPSCR value.
    auto source=line.rfind(" & ");
    REQUIRE(source!=std::string::npos);
    CHECK(line.substr(source+3).starts_with(mask));
    pos=end+1;
  }
  auto at=code.find("ctx.fpscr.StoreToHost(",pos);
  REQUIRE(at!=std::string::npos);
  CHECK(code.substr(at,code.find(';',at)-at).find("LoadFromHost")==std::string::npos);
}
// METRO_SCALAR_RUNTIME_TESTS
REX_TEST_CASE("metro_scalar_codegen: rounding update preserves actual host FP control",
              "[ppc][metro_scalar_codegen]") {
  const RestoreCSR restore;
  rex::ppc::FPSCRRegister fpscr{};
  using FPSCR=rex::ppc::FPSCRRegister;
  fpscr.InitHost();
  for(bool flush:{false,true}) {
    fpscr.SetFlushMode(flush);
    const u32 original=FPSCR::Platform::GetCSR();
    for(u32 rn=0;rn<4;++rn) {
      // Stale cached flush bits deliberately differ from the real host.
      fpscr.csr=FPSCR::Platform::GetCSR() ^ static_cast<u32>(FPSCR::kFlushMask);
      const u32 before=FPSCR::Platform::GetCSR();
      fpscr.StoreToHost(rn);
      const u32 after=FPSCR::Platform::GetCSR();
      CHECK((after & ~FPSCR::kRoundMaskVal)==(before & ~FPSCR::kRoundMaskVal));
      CHECK(fpscr.LoadFromHost()==rn);
    }
    CHECK((FPSCR::Platform::GetCSR() & FPSCR::kFlushMask)==(original & FPSCR::kFlushMask));
  }
}
