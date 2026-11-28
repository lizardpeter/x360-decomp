
REX_TEST_CASE_METHOD(Fixture, "Original partition-relative profile file reaches read-only STFS mount",
                     "[filesystem][metro_stfs_open_file]") {
  auto bytes=rex::platform::ReadHostFile(rex::test::GetFixtureFolder()/"stfs_con.bin");
  REQUIRE(bytes);
  auto host=GetTemp()/"storage";
  auto parent=host/"E000000000000001"/"FFFE07D1"/"00010000";
  std::filesystem::create_directories(parent);
  REQUIRE(rex::platform::WriteHostFile(parent/"E000000000000001",*bytes));
  auto firmware=GetTemp()/"firmware";
  std::filesystem::create_directories(firmware);
  auto& fs=GetFileSystem();
  REQUIRE(fs.Mount({"\\Device\\Harddisk0\\Partition1",ProviderType::kHostDirectory,firmware,MountFlags::kNone,{}}));
  REQUIRE(fs.Mount({"\\Device\\MetroProfileContent",ProviderType::kHostDirectory,host,MountFlags::kWritable,{}}));
  REQUIRE(fs.Link("\\Device\\Harddisk0\\Partition1\\Content","\\Device\\MetroProfileContent"));
  auto partition=Open("\\Device\\Harddisk0\\Partition1");
  auto content=fs.OpenRelative(*partition.file,"Content",{});
  REQUIRE(content);
  auto directories=content->file->List("E*");
  REQUIRE(directories);
  auto entry=(*directories)->Next();
  REQUIRE(entry);
  CHECK(entry->name=="E000000000000001");
  auto file=fs.OpenRelative(*content->file,"E000000000000001\\FFFE07D1\\00010000\\E000000000000001",
                           {.access=Access::kReadData,.require_file=true});
  REQUIRE(file);
  REQUIRE(fs.MountStfsFile("\\Device\\MetroProfileCheck",*file->file));
  file->file.reset();
  {
    auto root=Open("\\Device\\MetroProfileCheck");
    auto child=fs.OpenRelative(*root.file,"a.txt",{.access=Access::kReadData});
    REQUIRE(child);
    CHECK(ReadText(*child->file)=="alpha\n");
    std::array<rex::u8,1> invalid{0};
    CHECK_FALSE(child->file->Write(invalid,0));
  }
  REQUIRE(fs.Unmount("\\Device\\MetroProfileCheck"));
  CHECK_FALSE(fs.Stat("\\Device\\MetroProfileCheck"));
  CHECK(std::filesystem::is_empty(firmware));
  auto unchanged=rex::platform::ReadHostFile(parent/"E000000000000001");
  REQUIRE(unchanged);
  CHECK(*unchanged==*bytes);
}
