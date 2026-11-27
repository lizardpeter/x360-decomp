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
                       CREATE_END_OLD, "u32 NtOpenFile_entry(", DISMOUNT_OLD])
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
    def test_file_cursor(self):
        source="\n".join(['#include <rex/kernel/title_runtime.h>',READ_CURSOR_OLD,
                          WRITE_CURSOR_OLD,VIRTUAL_READ_OLD])
        result=patch_file(source)
        self.assertIn(READ_CURSOR_NEW,result)
        self.assertIn(WRITE_CURSOR_NEW,result)
        self.assertIn("GetWritableSpan",result)
        with self.assertRaises(ValueError):patch_file(result)
    def test_storage_notification_contract(self):
        result=patch_storage_notifications(NOTIFICATION_STUB)
        self.assertIn(NOTIFICATION_ENTRY,result)
        self.assertNotIn(NOTIFICATION_STUB,result)
        self.assertIn("X_STATUS_NOT_SUPPORTED",result)
        self.assertNotIn("X_STATUS_SUCCESS",result)
        with self.assertRaises(ValueError):patch_storage_notifications(result)
if __name__=="__main__":unittest.main()
