import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from patch_metro_io_runtime import *

class IoRuntime(unittest.TestCase):
    def test_device_and_offsets(self):
        text="\n".join([IO_HEADER,READ_OFFSET_OLD,WRITE_START,IO_START,
                       ATA_BRANCH,"QueueCompletionAPC",IO_END,
                       "                            MappedU32 segment_array, u32 length, MappedU64 byte_offset_ptr) {\n  X_STATUS result = X_STATUS_SUCCESS;",
                       "byte_offset_ptr ? static_cast<u64>(*byte_offset_ptr) : -1",
                       "byte_offset_ptr ? static_cast<u64>(*byte_offset_ptr) : -1",
                       "byte_offset_ptr ? static_cast<u64>(*byte_offset_ptr) : -1",
                       "u32 NtCreateFile_entry(",
                       CREATE_START_OLD,
                       "if (object_attrs->root_directory != 0 && object_attrs->root_directory != 1) use(object_attrs->root_directory);",
                       CREATE_END_OLD, OPEN_FILE_OLD, DISMOUNT_OLD])
        result=patch_io(text)
        self.assertIn(IO_BODY,result)
        self.assertNotIn("REX_ASSERT_ALWAYS",IO_BODY)
        self.assertIn("X_STATUS_NOT_SUPPORTED",IO_BODY)
        self.assertLess(IO_BODY.index("GetWritableSpan"),IO_BODY.index("memory.Store"))
        self.assertEqual(result.count("guest_memory.Load<be_u64>"),3)
        self.assertNotIn("*byte_offset_ptr",result)
        self.assertIn(CREATE_HELPER,result)
        self.assertIn(CREATE_START_NEW,result)
        self.assertIn(CREATE_END_NEW,result)
        self.assertIn(DISMOUNT_NEW,result)
        self.assertNotIn("object_attrs->root_directory",result)
        self.assertNotIn(DISMOUNT_OLD,result)
        with self.assertRaises(ValueError):patch_io(result)
    def test_original_six_argument_open(self):
        out=patch_open_file(OPEN_FILE_OLD)
        self.assertIn("u32 share_access,",out)
        self.assertIn("share_access, std::to_underlying",out)
        self.assertIn("open_options",out)
        with self.assertRaises(ValueError):patch_open_file(out)
    def test_file_cursor(self):
        source="\n".join(['#include <rex/kernel/title_runtime.h>',READ_CURSOR_OLD,
                          WRITE_CURSOR_OLD,VIRTUAL_READ_OLD])
        result=patch_file_cursor(source)
        self.assertIn(READ_CURSOR_NEW,result)
        self.assertIn(WRITE_CURSOR_NEW,result)
        self.assertIn("GetWritableSpan",result)
        with self.assertRaises(ValueError):patch_file_cursor(result)
    def test_metadata_patch_is_scoped_to_file_query(self):
        source="\n".join([IO_HEADER,"u32 NtQueryInformationFile_entry(",
            "  info_ptr.Zero(info_length);","    case XFileNetworkOpenInformation: {",
            "u32 GetSetFileMinimumLength(","  info_ptr.Zero(info_length);"])
        result=patch_file_information(source)
        self.assertIn("case XFileBasicInformation: {",result)
        self.assertIn("case XFileAllocationInformation: {",result)
        self.assertIn("info_ptr.Zero(minimum_length)",result)
        self.assertEqual(result.count("info_ptr.Zero(info_length)"),1)
        self.assertIn("GetWritableSpan(output,info_length)",result)
        with self.assertRaises(ValueError):patch_file_information(result)
    def test_storage_notification_contract(self):
        result=patch_storage_notifications(NOTIFICATION_STUB)
        self.assertIn(NOTIFICATION_ENTRY,result)
        self.assertNotIn(NOTIFICATION_STUB,result)
        self.assertIn("X_STATUS_NOT_SUPPORTED",result)
        self.assertNotIn("X_STATUS_SUCCESS",result)
        with self.assertRaises(ValueError):patch_storage_notifications(result)
    def test_profile_mount_routes_explicit_alias_and_respects_provider_ownership(self):
        source="\n".join([RELATIVE_RENAME_OLD,RELATIVE_RENAME_REJECT_OLD,MOUNT_ROOT_OLD,RELATIVE_OPEN_OLD,CROSS_PROVIDER_CHILD_OLD,CROSS_PROVIDER_READONLY_OLD,
          "  return Opened{std::make_unique<NodeFile>(*node, access, std::move(stream)), action};",
          "  return std::unique_ptr<IDirectory>(std::make_unique<NodeDirectory>(*node, pattern));",
          "Result<void> FileSystem::Mount(const MountEntry& entry) {"])
        result=patch_filesystem(source)
        self.assertNotIn("FindLink(absolute)",result)
        self.assertIn("ChildMountEntries(*node)",result)
        self.assertIn("mount && mount->relative.empty()",result)
        self.assertIn("node = &mount->provider->GetRoot()",result)
        self.assertIn("resolved->provider == &directory.GetProvider()",result)
        self.assertIn("utf8_equal_case(base, parent)",result)
        self.assertIn("for (const auto& link : links_)",result)
        self.assertIn("for (const auto& provider : providers_)",result)
        self.assertIn("resolved->provider != &root_node.GetProvider()",result)
        self.assertIn("parent->GetProvider() == &node->GetProvider()",result)
        self.assertIn("root_node.IsDirectory()",result)
        self.assertIn("OpenFrom(nullptr, absolute, options)",result)
        with self.assertRaises(ValueError):patch_filesystem(result)
    def test_system_entropy_replaces_constant_and_links_os_provider(self):
        source="#include <rex/platform.h>\n"+RANDOM_OLD
        patched=patch_system_entropy(source)
        self.assertNotIn("0xFD",patched)
        self.assertIn("GetWritableSpan(address, buf_size)",patched)
        self.assertIn("BCryptGenRandom",patched)
        self.assertIn("BCRYPT_USE_SYSTEM_PREFERRED_RNG",patched)
        self.assertIn("getrandom(output, chunk, 0)",patched)
        self.assertIn("errno == EINTR",patched)
        self.assertIn("remaining -= done",patched)
        self.assertIn("arc4random_buf",patched)
        self.assertIn("std::abort()",patched)
        self.assertIn("if (!buf_size) return;",patched)
        self.assertNotIn("std::rand(",patched)
        self.assertEqual(patch_entropy_linkage("target_link_libraries(${kernel_target} PRIVATE ws2_32 winmm)"),
                         "target_link_libraries(${kernel_target} PRIVATE ws2_32 winmm bcrypt)")
        with self.assertRaises(ValueError):patch_system_entropy(patched)
    def test_stfs_verified_request_abi_never_fabricates_success(self):
        patched=patch_stfs_contract(STFS_OLD)
        self.assertEqual(patched,STFS_NEW)
        self.assertIn("request_bytes != 88",patched)
        self.assertIn("GetReadOnlySpan(request, request_bytes)",patched)
        self.assertIn("GetWritableSpan(request, request_bytes)",patched)
        self.assertIn("ioctl > 5",patched)
        self.assertNotIn("X_STATUS_SUCCESS",patched)
        self.assertNotIn("memory.Store",patched)
        with self.assertRaises(ValueError):patch_stfs_contract(patched)
    def test_profile_relative_rename_resolves_destination_provider(self):
        result=patch_relative_rename(RELATIVE_RENAME_OLD+"\n"+RELATIVE_RENAME_REJECT_OLD)
        self.assertIn("ResolveMount(target_parent)",result)
        self.assertIn("resolved.provider != &node.GetProvider()",result)
        self.assertIn("StartsWithComponents(target_parent, root_path)",result)
        self.assertNotIn(RELATIVE_RENAME_REJECT_OLD,result)
    def test_set_information_checks_extent_and_status(self):
        original="u32 NtSetInformationFile_entry(\n"+"\n".join([SET_START_OLD,SET_RENAME_OLD,
            SET_UNSUPPORTED_OLD,SET_EOF_OLD,SET_ALLOCATION_OLD,SET_POSITION_OLD,SET_BASIC_OLD])+"\nu32 GetQueryVolumeMinimumLength("
        result=patch_set_information(original)
        self.assertIn("GetReadOnlySpan(input,minimum_length)",result)
        self.assertIn("GetReadOnlySpan(name->pointer,length)",result)
        self.assertIn("X_STATUS_NOT_SUPPORTED",result)
        self.assertEqual(result.count("0x7fffffffffffffff"),3)
        self.assertIn("if (info->attributes)",result)
        with self.assertRaises(ValueError):patch_set_information(result)
    def test_offline_endpoint_cannot_report_device_control_success(self):
        self.assertIn("kOfflineEndpoint",str(OFFLINE_ENDPOINT_PATCHES))
        self.assertIn("FileAttributes::kDevice",IO_BODY)
        self.assertIn("return X_STATUS_NOT_SUPPORTED",IO_BODY)
        self.assertLess(IO_BODY.index("METRO_OFFLINE_DEVICE"),IO_BODY.index("kGeometry"))
        provider=OFFLINE_ENDPOINT_PATCHES["src/filesystem/null_provider.cpp"]
        self.assertIn("offline device cannot read",provider[0][1])
        self.assertIn("offline device cannot write",provider[0][1])
        self.assertNotIn("return Ok()",provider[0][1])
    def test_storage_queries_bound_and_retry(self):
        source="\n".join([ATTR_QUERY_OLD,DIRECTORY_QUERY_OLD,DIRECTORY_COUNT_OLD])
        patched=patch_storage_queries(source)
        self.assertIn("CheckedAnsiPath",patched)
        self.assertIn("GetWritableSpan(output,length)",patched)
        self.assertIn("offsetof(X_FILE_DIRECTORY_INFORMATION,file_name)",patched)
        self.assertNotIn("info = length;",patched)
        obj=patch_directory_object("\n".join([DIRECTORY_OBJECT_OLD,DIRECTORY_OVERFLOW_OLD,
            DIRECTORY_RETRY_OLD,DIRECTORY_PATTERN_OLD,DIRECTORY_SET_FIND_OLD]))
        self.assertIn("pending_directory_entry=std::move(entry)",obj)
        self.assertNotIn("REX_ASSERT_ALWAYS",obj)
        self.assertIn("pending_directory_entry.reset()",obj)
        volume=patch_volume_query("u32 NtQueryVolumeInformationFile_entry(\n"+VOLUME_QUERY_OLD)
        self.assertIn("info_ptr.Zero(minimum_length)",volume)
        with self.assertRaises(ValueError):patch_storage_queries(patched)
    def test_pirs_public_provider_is_bounded_and_real(self):
        from patch_metro_public_verification import STUB,INCLUDE,NAMESPACE,CLOSE,EXPORT,corrected,guest_public_blob,modulus,guest_number,vector
        key=guest_public_blob()
        self.assertEqual(len(key),272)
        self.assertEqual(key[:8],bytes.fromhex("0000002000000003"))
        self.assertEqual(int.from_bytes(key[-8:],"big"),modulus()>>1984)
        self.assertEqual(int.from_bytes(key[16:24],"big"),modulus()&((1<<64)-1))
        self.assertEqual(len(vector()[0]),256)
        self.assertEqual(len(vector()[1]),256)
        source=INCLUDE+"\n"+NAMESPACE+"\n"+STUB+"\n"+CLOSE
        out=corrected(source)
        self.assertEqual(out.count(NAMESPACE),1)
        self.assertLess(out.index("XeKeysGetKey_entry(u32"),out.index(CLOSE))
        self.assertLess(out.index(CLOSE),out.index(EXPORT))
        with self.assertRaises(ValueError):corrected(INCLUDE+"\n"+STUB)
        self.assertNotIn(STUB,out)
        self.assertIn("id!=0x39u",out)
        self.assertIn("X_STATUS_NOT_SUPPORTED",out)
        self.assertIn("GetWritableSpan",out)
        self.assertNotIn("XeCryptBnQwBeSigVerify_entry",out)
        with self.assertRaises(ValueError):corrected(out)
    def test_encoded_signature_oracle_and_patch(self):
        from patch_metro_public_verification import (PUBLIC_TEST_VECTORS,TEST_HASH,TEST_SALT,
            reference_signature_result,corrected_signature_verifier,SIG_VERIFY_OLD,SIG_VERIFY_NEW)
        import hashlib
        def rc4(key,data):
            s=list(range(256))
            j=0
            for i in range(256):
                j=(j+s[i]+key[i%len(key)])&255
                s[i],s[j]=s[j],s[i]
            i=j=0
            out=bytearray()
            for b in data:
                i=(i+1)&255
                j=(j+s[i])&255
                s[i],s[j]=s[j],s[i]
                out.append(b^s[(s[i]+s[j])&255])
            return bytes(out)
        digest=hashlib.sha1(bytes(8)+TEST_HASH+TEST_SALT).digest()
        block=bytearray(rc4(digest,bytes(224)+b"\1"+TEST_SALT)+digest+b"\xbc")
        block[0]&=127
        expected=int.from_bytes(block,"big")
        for e,n,s in PUBLIC_TEST_VECTORS:
            n,s=int(n,16),int(s,16)
            self.assertEqual(reference_signature_result(s,e,n),expected)
            self.assertNotEqual(pow(s,e,n),expected)
            self.assertNotEqual(reference_signature_result(s^1,e,n),expected)
            self.assertIsNone(reference_signature_result(n,e,n))
        self.assertEqual(corrected_signature_verifier(SIG_VERIFY_OLD),SIG_VERIFY_NEW)
        self.assertNotIn("XeCryptBnQwNeRsaPubCrypt_entry",SIG_VERIFY_NEW)
        self.assertIn("GetReadOnlySpan",SIG_VERIFY_NEW)
        self.assertIn("std::memcmp",SIG_VERIFY_NEW)
        with self.assertRaises(ValueError):corrected_signature_verifier(SIG_VERIFY_NEW)

if __name__=="__main__":unittest.main()
