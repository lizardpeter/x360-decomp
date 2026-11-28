
#include "fixture_dir.h"
#include <rex/platform/file.h>

REX_TEST_CASE_METHOD(Fixture, "STFS mounts an already opened guest file without host path reopen",
                     "[filesystem][metro_stfs_open_file]") {
  auto bytes = rex::platform::ReadHostFile(rex::test::GetFixtureFolder() / "stfs_con.bin");
  REQUIRE(bytes);
  REQUIRE(rex::platform::WriteHostFile(GetTemp() / "profile.bin", *bytes));
  MountTemp(kRoot);
  auto source = Open("\\Device\\Test\\profile.bin");
  auto& fs = GetFileSystem();
  REQUIRE(fs.MountStfsFile("\\Device\\ProfileStfs0", *source.file));
  CHECK_FALSE(fs.MountStfsFile("\\device\\profilestfs0", *source.file));
  CHECK_FALSE(fs.MountStfsFile("\\Device\\Test", *source.file));
  CHECK_FALSE(fs.MountStfsFile("\\Device\\Test\\nested", *source.file));
  CHECK_FALSE(fs.MountStfsFile("game:", *source.file));
  CHECK_FALSE(fs.MountStfsFile("\\Device\\..", *source.file));
  source.file.reset();
  REQUIRE(fs.Remove("\\Device\\Test\\profile.bin"));
  CHECK(ReadText(*Open("\\Device\\ProfileStfs0\\a.txt").file) == "alpha\n");
  auto nested = Open("\\Device\\ProfileStfs0\\folder\\c.txt");
  CHECK(ReadText(*nested.file) == "charlie in folder\n");
  auto big = Open("\\Device\\ProfileStfs0\\big.bin", {.access = Access::kAllAccess});
  std::array<rex::u8, 32> sample{};
  auto read = big.file->Read(sample, 0x0FF0);
  REQUIRE(read);
  CHECK(*read == sample.size());
  for (size_t i = 0; i < sample.size(); ++i) {
    CHECK(sample[i] == static_cast<rex::u8>((0x0FF0 + i) % 251));
  }
  CHECK_FALSE(big.file->Write(sample, 0));
  auto mounts = fs.GetMounts();
  REQUIRE(mounts.size() == 2);
  CHECK(mounts.back().source.empty());
  CHECK(mounts.back().type == ProviderType::kSTFS);
  CHECK(mounts.back().flags == MountFlags::kNone);
  REQUIRE(fs.Unmount("\\Device\\ProfileStfs0"));
  CHECK_FALSE(fs.Open("\\Device\\ProfileStfs0\\a.txt", {}));
  CHECK(ReadText(*nested.file) == "charlie in folder\n");
}

REX_TEST_CASE_METHOD(Fixture, "Rejected STFS open-file mounts never publish a provider",
                     "[filesystem][metro_stfs_open_file]") {
  auto bytes = rex::platform::ReadHostFile(rex::test::GetFixtureFolder() / "stfs_con.bin");
  REQUIRE(bytes);
  bytes->resize(0xA800);
  REQUIRE(rex::platform::WriteHostFile(GetTemp() / "truncated.bin", *bytes));
  WriteHost(GetTemp() / "garbage.bin", "garbage");
  std::filesystem::create_directories(GetTemp() / "folder");
  MountTemp(kRoot);
  auto& fs = GetFileSystem();
  for (auto path : {"\\Device\\Test\\truncated.bin", "\\Device\\Test\\garbage.bin",
                    "\\Device\\Test\\folder"}) {
    auto source = Open(path);
    CHECK_FALSE(fs.MountStfsFile("\\Device\\RejectedStfs", *source.file));
    CHECK(fs.GetMounts().size() == 1);
    CHECK_FALSE(fs.Stat("\\Device\\RejectedStfs"));
  }
  auto valid = rex::platform::ReadHostFile(rex::test::GetFixtureFolder() / "stfs_con.bin");
  REQUIRE(valid);
  REQUIRE(rex::platform::WriteHostFile(GetTemp() / "valid.bin", *valid));
  auto write_only = Open("\\Device\\Test\\valid.bin", {.access = Access::kWriteData});
  CHECK_FALSE(fs.MountStfsFile("\\Device\\RejectedStfs", *write_only.file));
  CHECK(fs.GetMounts().size() == 1);
}


REX_TEST_CASE_METHOD(Fixture, "STFS snapshot rejects incomplete or unsafe directory data before publication",
                     "[filesystem][metro_stfs_open_file]") {
  auto bytes=rex::platform::ReadHostFile(rex::test::GetFixtureFolder()/"stfs_con.bin");
  REQUIRE(bytes);
  REQUIRE(bytes->size()==65536);
  auto be32=[&](size_t p) {
    return (rex::u32((*bytes)[p])<<24)|(rex::u32((*bytes)[p+1])<<16)|
           (rex::u32((*bytes)[p+2])<<8)|(*bytes)[p+3];
  };
  const size_t data_start=(size_t(be32(0x340))+0xfff)&~size_t(0xfff);
  const unsigned copies=((*bytes)[0x37b]&1)?1:2;
  const unsigned directory=(*bytes)[0x37e]|(unsigned((*bytes)[0x37f])<<8)|
                           (unsigned((*bytes)[0x380])<<16);
  REQUIRE(directory<170);
  const size_t table=data_start+(directory+copies)*4096;
  REQUIRE(table+4096<=bytes->size());
  size_t file_entry=0;
  for (size_t p=table;p<table+4096 && (*bytes)[p];p+=64) {
    if (!((*bytes)[p+40]&0x80) &&
        ((*bytes)[p+52]||(*bytes)[p+53]||(*bytes)[p+54]||(*bytes)[p+55])) {
      file_entry=p;break;
    }
  }
  REQUIRE(file_entry!=0);
  // Find two distinct siblings in the fixture without changing either
  // entry's block chain, size, or directory flag.
  size_t first_name=0,second_name=0;
  for (size_t a=table;a<table+4096 && (*bytes)[a] && !second_name;a+=64) {
    for (size_t b=a+64;b<table+4096 && (*bytes)[b];b+=64) {
      if ((*bytes)[a+50]==(*bytes)[b+50] && (*bytes)[a+51]==(*bytes)[b+51]) {
        first_name=a;second_name=b;break;
      }
    }
  }
  REQUIRE(first_name!=0);
  REQUIRE(second_name!=0);
  MountTemp(kRoot);
  auto& fs=GetFileSystem();
  for (unsigned mutation=0;mutation<6;++mutation) {
    auto broken=*bytes;
    if (mutation==0) { // unsafe name
      broken[file_entry]='/';
    } else if (mutation==1) { // file extent outside the snapshot
      broken[file_entry+47]=0xfe;broken[file_entry+48]=0xff;broken[file_entry+49]=0x7f;
    } else if (mutation==2) { // impossible directory extent
      broken[0x37c]=0xff;broken[0x37d]=0xff;
    } else if (mutation==3) { // directory block reused as file data
      broken[file_entry+47]=static_cast<rex::u8>(directory);
      broken[file_entry+48]=0;broken[file_entry+49]=0;
    } else { // exact duplicate or case-only duplicate sibling
      const unsigned length=broken[first_name+40]&0x3f;
      REQUIRE(length>0);
      REQUIRE(length<=40);
      for (unsigned i=0;i<40;++i) {
        auto ch=broken[first_name+i];
        if (mutation==5 && i<length && ch>='a' && ch<='z') ch-=32;
        else if (mutation==5 && i<length && ch>='A' && ch<='Z') ch+=32;
        broken[second_name+i]=ch;
      }
      broken[second_name+40]=static_cast<rex::u8>((broken[second_name+40]&0xc0)|length);
    }
    const auto name="broken"+std::to_string(mutation)+".bin";
    REQUIRE(rex::platform::WriteHostFile(GetTemp()/name,broken));
    auto source=Open("\\Device\\Test\\"+name);
    CHECK_FALSE(fs.MountStfsFile("\\Device\\RejectedStfs",*source.file));
    CHECK_FALSE(fs.Stat("\\Device\\RejectedStfs"));
    CHECK(fs.GetMounts().size()==1);
  }
}
