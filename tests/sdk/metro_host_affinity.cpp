// Sparse host IDs must not be confused with the Xbox's six virtual CPUs.
REX_TEST_CASE("metro_host_affinity: maps six virtual CPUs to allowed host IDs", "[base][metro_host_affinity]") {
  using rex::platform::MapGuestProcessor;
  constexpr rex::u64 sparse=(rex::u64{1}<<2)|(rex::u64{1}<<9)|(rex::u64{1}<<31)|
      (rex::u64{1}<<32)|(rex::u64{1}<<47)|(rex::u64{1}<<63);
  constexpr std::array<unsigned,6> ids{2,9,31,32,47,63};
  for(unsigned i=0;i<ids.size();++i) {
    CHECK(MapGuestProcessor(sparse,i)==(rex::u64{1}<<ids[i]));
    CHECK(MapGuestProcessor(0x3f,i)==(rex::u64{1}<<i));
    CHECK(MapGuestProcessor(0x1f,i)==0);
    CHECK(MapGuestProcessor(0,i)==0);
  }
  CHECK(MapGuestProcessor(sparse,6)==0);
  CHECK(MapGuestProcessor(sparse,0xffffffffu)==0);
  CHECK(MapGuestProcessor(~rex::u64{0},5)==32);
}

REX_TEST_CASE("metro_host_affinity: live map only contains distinct permitted CPUs", "[base][metro_host_affinity]") {
  const auto allowed=rex::platform::GetAvailableProcessorMask();
  rex::u64 selected=0;
  for(unsigned i=0;i<6;++i) {
    const auto target=rex::platform::MapGuestProcessor(allowed,i);
    CHECK((target&~allowed)==0);
    CHECK((target&selected)==0);
    CHECK(!target || (target&(target-1))==0);
    selected|=target;
  }
}
