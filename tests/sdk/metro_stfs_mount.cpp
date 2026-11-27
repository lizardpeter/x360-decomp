
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
