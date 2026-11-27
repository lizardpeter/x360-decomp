// Real original font authentication: only locally staged, verified original
// public signed payloads. Never print the signature, digest or font bytes.
#include <cstdlib>
#include <rex/platform/file.h>

REX_TEST_CASE("metro_io_runtime: actual original XTT signatures through native guest exports",
              "[kernel][crypt][metro_original_fonts]") {
  const char* root=std::getenv("METRO_ORIGINAL_FONT_FIXTURES");
  REQUIRE(root!=nullptr);
  struct Case { const char* name; u32 length; };
  constexpr Case cases[]={
    {"SegoeXbox-Light.xtt.bin",3836},
    {"XenonCLatin.xtt.bin",48892},
    {"XenonJKLatin.xtt.bin",98044},
  };
  for (const auto& item:cases) {
    INFO(item.name);
    const auto data=rex::platform::ReadHostFile(std::filesystem::path(root)/item.name);
    REQUIRE(data);
    REQUIRE(data->size()==288u+item.length);
    KernelFixture fixture;
    fixture.RunOnGuestThread([&](Caller& c) {
      const u32 key=c.Alloc(272),length=c.Alloc(4),sig=c.Alloc(256),
                salt=c.Alloc(12),hash=c.Alloc(20),payload=c.Alloc(item.length);
      auto word=[&](u32 offset) {
        return (u32((*data)[offset])<<24)|(u32((*data)[offset+1])<<16)|
               (u32((*data)[offset+2])<<8)|u32((*data)[offset+3]);
      };
      auto copy=[&](u32 target,u32 offset,u32 count) {
        for (u32 i=0;i<count;i+=4)c.Store32(target+i,word(offset+i));
      };
      copy(sig,0,256);
      copy(salt,256,12);
      copy(payload,288,item.length);
      c.Store32(length,272);
      REQUIRE(c.Kernel("XeKeysGetKey",{0x39,key,length})==0);
      c.Kernel("XeCryptRotSumSha",{payload,item.length,0,0,hash,20});
      // Keep mismatches opaque: only a boolean is printed on failure.
      bool hash_matches=true;
      for(u32 i=0;i<20;i+=4)hash_matches &= c.Load32(hash+i)==word(268+i);
      REQUIRE(hash_matches);
      REQUIRE(c.Kernel("XeCryptBnQwBeSigVerify",{sig,hash,salt,key})==1);
      const u32 offset=(item.length/2)&~3u;
      c.Store32(payload+offset,word(288+offset)^1u);
      c.Kernel("XeCryptRotSumSha",{payload,item.length,0,0,hash,20});
      CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{sig,hash,salt,key})==0);
      c.Store32(payload+offset,word(288+offset));
      c.Kernel("XeCryptRotSumSha",{payload,item.length,0,0,hash,20});
      CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{sig,hash,salt,key})==1);
    });
  }
}
