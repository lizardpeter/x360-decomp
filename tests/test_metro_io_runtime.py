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
        source="\n".join([RELATIVE_OPEN_OLD,CROSS_PROVIDER_CHILD_OLD,CROSS_PROVIDER_READONLY_OLD])
        result=patch_filesystem(source)
        self.assertIn("FindLink(absolute)",result)
        self.assertIn("resolved->provider != &root_node.GetProvider()",result)
        self.assertIn("parent->GetProvider() == &node->GetProvider()",result)
        self.assertIn("root_node.IsDirectory()",result)
        self.assertIn("OpenFrom(nullptr, absolute, options)",result)
        with self.assertRaises(ValueError):patch_filesystem(result)
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
if __name__=="__main__":unittest.main()
