#!/usr/bin/env python3
"""Correct native hosted file I/O contracts used by original XAM.

The earlier device-control correction only handled the first observed ATA
request. This revision handles unsupported requests as errors instead of
host assertions, validates guest result buffers, and fixes file cursor
updates when the caller supplies an explicit byte offset.
"""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION
from patch_metro_device_control import NEW as ATA_BRANCH, OLD as UNKNOWN_BRANCH

def replace(source, old, new):
    if source.count(old)!=1 or new in source:
        raise ValueError("unexpected I/O patch anchor: "+old[:80])
    return source.replace(old,new,1)

IO_HEADER = '#include <rex/kernel/title_runtime.h>'
IO_HEADER_NEW = IO_HEADER + '\n#include <rex/kernel/guest_memory.h>\n#include <cstring>'
IO_START = '  const u32 cache_size = 0xFF000;'
IO_END = '\n}\n\n/**\n * Allocates a device structure'
IO_BODY = """  // Preserve the established utility-drive geometry contract. Other
  // hosted files do not expose a physical device control provider.
  constexpr u32 cache_size = 0xFF000;
  constexpr u32 kGeometry = 0x70000;
  constexpr u32 kPartition = 0x74004;
  if (io_control_code != kGeometry && io_control_code != kPartition) {
    // No physical command is forwarded, and no guest output or completion
    // is fabricated for a request that the hosted provider cannot perform.
    REXKRNL_WARN("METRO_IOCTL unsupported code=0x{:08X} input_bytes={} output_bytes={}",
                 io_control_code, input_buffer_len, output_buffer_len);
    return X_STATUS_NOT_SUPPORTED;
  }

  const u32 information = io_control_code == kGeometry
      ? sizeof(X_DISK_CACHE_GEOMETRY) : sizeof(X_DISK_CACHE_PARTITION);
  if (output_buffer_len < information) return X_STATUS_BUFFER_TOO_SMALL;
  auto& memory = kernel::GetCurrent().GetGuestMemory();
  const u32 output_address = output_buffer.GetGuestAddress();
  if (!output_address || !memory.GetWritableSpan(output_address, information))
    return X_STATUS_ACCESS_VIOLATION;
  if (io_status_block) {
    if (!memory.GetWritableSpan(io_status_block, sizeof(X_IO_STATUS_BLOCK)))
      return X_STATUS_ACCESS_VIOLATION;
    if (u64{output_address} < u64{io_status_block} + sizeof(X_IO_STATUS_BLOCK) &&
        u64{io_status_block} < u64{output_address} + information)
      return X_STATUS_INVALID_PARAMETER;
  }
  auto event = kernel::GetCurrent().GetObjectTable().Get<EventObject>(event_handle);
  if (event_handle && !event) return X_STATUS_INVALID_HANDLE;
  if ((apc_routine & ~3u) && !KernelThread::GetCallingThread())
    return X_STATUS_INVALID_PARAMETER;

  // Checked spans are resolved before mutation. Use a local, endian-aware
  // object rather than dereferencing an unvalidated mapped guest pointer.
  if (io_control_code == kGeometry) {
    X_DISK_CACHE_GEOMETRY geometry{};
    geometry.sector_count = cache_size / 512;
    geometry.sector_size = 512;
    if (!memory.Store(output_address, geometry)) return X_STATUS_ACCESS_VIOLATION;
  } else {
    X_DISK_CACHE_PARTITION partition{};
    partition.start_offset = 0;
    partition.length = cache_size;
    if (!memory.Store(output_address, partition)) return X_STATUS_ACCESS_VIOLATION;
  }
  if (io_status_block) {
    X_IO_STATUS_BLOCK status_block{};
    status_block.status = X_STATUS_SUCCESS;
    status_block.information = information;
    if (!memory.Store(io_status_block, status_block)) return X_STATUS_ACCESS_VIOLATION;
  }
  if (event) event->Set();
  QueueCompletionAPC(apc_routine, apc_context, io_status_block, X_STATUS_SUCCESS);
  return X_STATUS_SUCCESS;"""

READ_OFFSET_OLD = "  u64 byte_offset = byte_offset_ptr ? static_cast<u64>(*byte_offset_ptr) : 0;"
READ_OFFSET_NEW = """  auto& guest_memory = kernel::GetCurrent().GetGuestMemory();
  u64 byte_offset = ~u64{0};
  if (const auto address = byte_offset_ptr.GetGuestAddress()) {
    auto value = guest_memory.Load<be_u64>(address);
    if (!value) return X_STATUS_ACCESS_VIOLATION;
    byte_offset = *value;
  }
  if (const auto address = io_status_block.GetGuestAddress();
      address && !guest_memory.GetWritableSpan(address, sizeof(X_IO_STATUS_BLOCK)))
    return X_STATUS_ACCESS_VIOLATION;"""
WRITE_START = """                      u32 buffer_length, MappedU64 byte_offset_ptr) {
  X_STATUS result = X_STATUS_SUCCESS;"""
WRITE_NEW = """                      u32 buffer_length, MappedU64 byte_offset_ptr) {
  auto& guest_memory = kernel::GetCurrent().GetGuestMemory();
  u64 byte_offset = ~u64{0};
  if (const auto address = byte_offset_ptr.GetGuestAddress()) {
    auto value = guest_memory.Load<be_u64>(address);
    if (!value) return X_STATUS_ACCESS_VIOLATION;
    byte_offset = *value;
  }
  if (const auto address = io_status_block.GetGuestAddress();
      address && !guest_memory.GetWritableSpan(address, sizeof(X_IO_STATUS_BLOCK)))
    return X_STATUS_ACCESS_VIOLATION;
  if (buffer_length && (!buffer.GetGuestAddress() ||
      !guest_memory.GetReadOnlySpan(buffer.GetGuestAddress(), buffer_length)))
    return X_STATUS_ACCESS_VIOLATION;
  X_STATUS result = X_STATUS_SUCCESS;"""
READ_CURSOR_OLD = """            if (byte_offset) {
              position_ = byte_offset;
            }
            position_ += bytes_read;"""
READ_CURSOR_NEW = """            position_ = byte_offset + bytes_read;"""
WRITE_CURSOR_OLD = "    position_ += bytes_written;"
WRITE_CURSOR_NEW = "    position_ = byte_offset + bytes_written;"
VIRTUAL_READ_OLD = """        } else {
          auto read = file->Read(
              std::span<u8>(buffer_physical_heap"""
VIRTUAL_READ_NEW = """        } else if (!buffer_physical_heap &&
                   !runtime.GetGuestMemory().GetWritableSpan(buffer_address, buffer_length)) {
          // Keep the physical coherence path intact; virtual writes must
          // also be checked instead of faulting in the hosted file provider.
          result = X_STATUS_ACCESS_VIOLATION;
        } else {
          auto read = file->Read(
              std::span<u8>(buffer_physical_heap"""

CREATE_START_OLD = """  if (!object_attrs) {
    // object_attrs is not optional, though some titles pass null.
    return X_STATUS_INVALID_PARAMETER;
  }
  if (creation_disposition > std::to_underlying(filesystem::Disposition::kOverwriteIf)) {
    return X_STATUS_INVALID_PARAMETER;
  }
  REX_ASSERT(handle_out != nullptr);

  auto object_name = kernel::GetCurrentState().GetAddressSpace()->TranslateVirtual<X_ANSI_STRING*>(
      object_attrs->name_ptr);

  auto target_path = StripDosDevicePrefix(
      kernel::TranslateAnsiPath(kernel::GetCurrentState().GetAddressSpace(), object_name));"""
CREATE_START_NEW = r"""  const u32 attributes_address = object_attrs.GetGuestAddress();
  const u32 handle_address = handle_out.GetGuestAddress();
  const u32 status_address = io_status_block.GetGuestAddress();
  if (!attributes_address || !handle_address ||
      creation_disposition > std::to_underlying(filesystem::Disposition::kOverwriteIf))
    return X_STATUS_INVALID_PARAMETER;
  auto& guest = kernel::GetCurrent().GetGuestMemory();
  if (!guest.GetWritableSpan(handle_address, sizeof(be_u32)) ||
      (status_address && !guest.GetWritableSpan(status_address, sizeof(X_IO_STATUS_BLOCK))))
    return X_STATUS_ACCESS_VIOLATION;
  if (status_address &&
      u64{handle_address} < u64{status_address} + sizeof(X_IO_STATUS_BLOCK) &&
      u64{status_address} < u64{handle_address} + sizeof(be_u32))
    return X_STATUS_INVALID_PARAMETER;
  const auto attributes = guest.Load<X_OBJECT_ATTRIBUTES>(attributes_address);
  if (!attributes) return X_STATUS_ACCESS_VIOLATION;
  std::string target_path;
  if (const auto status = CheckedAnsiPath(attributes->name_ptr, target_path);
      status != X_STATUS_SUCCESS) return status;"""
CREATE_HELPER = r"""// Read a counted guest name without translating unchecked guest pointers.
static X_STATUS CheckedAnsiPath(u32 address, std::string& path) {
  auto& guest = kernel::GetCurrent().GetGuestMemory();
  if (!address) return X_STATUS_INVALID_PARAMETER;
  auto name = guest.Load<X_ANSI_STRING>(address);
  if (!name) return X_STATUS_ACCESS_VIOLATION;
  const u16 length = name->length;
  if (length > static_cast<u16>(name->maximum_length))
    return X_STATUS_INVALID_PARAMETER;
  if (!length) return X_STATUS_OBJECT_NAME_INVALID;
  if (!name->pointer) return X_STATUS_ACCESS_VIOLATION;
  auto bytes = guest.GetReadOnlySpan(name->pointer, length);
  if (!bytes) return X_STATUS_ACCESS_VIOLATION;
  std::string copied(reinterpret_cast<const char*>(bytes->data()), bytes->size());
  if (copied.find('\0') != std::string::npos) return X_STATUS_OBJECT_NAME_INVALID;
  path = StripDosDevicePrefix(rex::string::TrimString(std::move(copied)));
  return X_STATUS_SUCCESS;
}

"""
CREATE_END_OLD = """  if (io_status_block) {
    io_status_block->status = result;
    io_status_block->information = static_cast<u32>(file_action);
  }

  *handle_out = handle;"""
CREATE_END_NEW = """  if (status_address) {
    X_IO_STATUS_BLOCK block{};
    block.status = result;
    block.information = static_cast<u32>(file_action);
    if (!guest.Store(status_address, block)) return X_STATUS_ACCESS_VIOLATION;
  }
  if (!guest.Store(handle_address, be_u32{handle})) return X_STATUS_ACCESS_VIOLATION;"""

DISMOUNT_OLD = """u32 IoDismountVolumeByFileHandle_entry(u32 handle) {
  REX_KERNEL_STUB("IoDismountVolumeByFileHandle({:#x})", static_cast<u32>(handle));
  return X_STATUS_SUCCESS;
}

u32 IoDismountVolumeByName_entry([[maybe_unused]] GuestPtrT<X_ANSI_STRING> name) {
  REX_KERNEL_STUB("IoDismountVolumeByName");
  return X_STATUS_SUCCESS;
}"""
DISMOUNT_NEW = r"""u32 IoDismountVolumeByFileHandle_entry(u32 handle) {
  const auto file = kernel::GetCurrent().GetObjectTable().Get(handle);
  if (!file) return X_STATUS_INVALID_HANDLE;
  if (file.GetType() != ObjectType::kFile) return X_STATUS_OBJECT_TYPE_MISMATCH;
  // The host-backed mount is not a console volume object. The SDK does not
  // yet track exclusive volume ownership or dismount/reopen transitions.
  REXKRNL_WARN("METRO_DISMOUNT unsupported file handle={:#x}", handle);
  return X_STATUS_NOT_SUPPORTED;
}

u32 IoDismountVolumeByName_entry(GuestPtrT<X_ANSI_STRING> name) {
  std::string path;
  if (const auto status = CheckedAnsiPath(name.GetGuestAddress(), path);
      status != X_STATUS_SUCCESS) return status;
  if (!IsValidPath(path, PathUse::kExisting)) return X_STATUS_OBJECT_NAME_INVALID;
  // Do not unmount the host's active resource tree or pretend it happened.
  auto volume = kernel::GetCurrentState().GetFileSystem()->GetVolume(path);
  if (!volume) return ToXStatus(volume.error());
  REXKRNL_WARN("METRO_DISMOUNT unsupported volume={}", path);
  return X_STATUS_NOT_SUPPORTED;
}"""

def patch_create_and_dismount(source):
    source=replace(source,CREATE_START_OLD,CREATE_START_NEW)
    source=replace(source,"u32 NtCreateFile_entry(",CREATE_HELPER+"u32 NtCreateFile_entry(")
    # Only the NtCreateFile body may use the validated local attributes.
    start=source.index("u32 NtCreateFile_entry(")
    end=source.index("u32 NtOpenFile_entry(",start)
    body=source[start:end]
    if body.count("object_attrs->root_directory")!=3:
        raise ValueError("unexpected root-directory argument use")
    body=body.replace("object_attrs->root_directory","attributes->root_directory")
    body=replace(body,CREATE_END_OLD,CREATE_END_NEW)
    source=source[:start]+body+source[end:]
    return replace(source,DISMOUNT_OLD,DISMOUNT_NEW)

def patch_io(source):
    if source.count(ATA_BRANCH)!=1:
        raise ValueError("expected prior narrow ATA correction")
    start=source.index(IO_START)
    end=source.index(IO_END,start)
    if source.find(IO_START,start+1)!=-1 or "QueueCompletionAPC" not in source[start:end]:
        raise ValueError("unexpected device-control body")
    source=source[:start]+IO_BODY+source[end:]
    source=replace(source,IO_HEADER,IO_HEADER_NEW)
    source=replace(source,READ_OFFSET_OLD,READ_OFFSET_NEW)
    source=replace(source,WRITE_START,WRITE_NEW)
    old="byte_offset_ptr ? static_cast<u64>(*byte_offset_ptr) : -1"
    # There is a third use in NtReadFileScatter. Patch its own argument
    # validation first, so no uninitialized local is introduced.
    scatter = """                            MappedU32 segment_array, u32 length, MappedU64 byte_offset_ptr) {
  X_STATUS result = X_STATUS_SUCCESS;"""
    scatter_new = """                            MappedU32 segment_array, u32 length, MappedU64 byte_offset_ptr) {
""" + READ_OFFSET_NEW + """
  X_STATUS result = X_STATUS_SUCCESS;"""
    source=replace(source,scatter,scatter_new)
    if source.count(old)!=3:raise ValueError("unexpected offset use")
    return patch_create_and_dismount(source.replace(old,"byte_offset"))

# File names only; no resource bytes, arbitrary host paths or user files.
RESOURCE_TRACE = r'''
static bool IsMetroUIResource(std::string_view name) {
  return name.ends_with(".xtt") || name.ends_with(".XTT") ||
         name.ends_with(".xzp") || name.ends_with(".XZP") ||
         name.ends_with(".xur") || name.ends_with(".XUR");
}
'''

def patch_file_information(source):
    source=replace(source,"#include <rex/kernel/title_runtime.h>",
        "#include <rex/kernel/title_runtime.h>\n#include <rex/kernel/guest_memory.h>")
    start=source.index("u32 NtQueryInformationFile_entry(")
    end=source.index("u32 GetSetFileMinimumLength(",start)
    prefix,query,suffix=source[:start],source[start:end],source[end:]
    source=replace(query,"  info_ptr.Zero(info_length);",
        """  auto& guest=kernel::GetCurrent().GetGuestMemory();
  const u32 output=info_ptr.GetGuestAddress(), iosb=io_status_block.GetGuestAddress();
  if (!output || !guest.GetWritableSpan(output,info_length) ||
      (iosb && !guest.GetWritableSpan(iosb,sizeof(X_IO_STATUS_BLOCK))))
    return X_STATUS_ACCESS_VIOLATION;
  if (iosb && u64{output}<u64{iosb}+sizeof(X_IO_STATUS_BLOCK) &&
      u64{iosb}<u64{output}+info_length)
    return X_STATUS_INVALID_PARAMETER;
  // Only the returned structure is owned by this query, not spare bytes
  // the caller may have reserved after it.
  info_ptr.Zero(minimum_length);""")
    source=replace(source,"    case XFileNetworkOpenInformation: {",
        """    case XFileBasicInformation: {
      file->file->Refresh();
      const auto entry=file->file->GetInfo();
      auto info=info_ptr.As<X_FILE_BASIC_INFORMATION*>();
      info->creation_time=entry.create_time;
      info->last_access_time=entry.access_time;
      info->last_write_time=entry.write_time;
      info->change_time=entry.write_time;
      info->attributes=std::to_underlying(entry.attributes);
      out_length=sizeof(*info);
      break;
    }
    case XFileAllocationInformation: {
      file->file->Refresh();
      auto info=info_ptr.As<X_FILE_ALLOCATION_INFORMATION*>();
      info->allocation_size=file->file->GetInfo().allocation_size;
      out_length=sizeof(*info);
      break;
    }
    case XFileNetworkOpenInformation: {""")
    return prefix+source+suffix

def patch_scatter(source):
    old="""  be_u32* segments = reinterpret_cast<be_u32*>(
      StateOf(runtime).GetAddressSpace()->TranslateVirtual(segments_address));

  u32 page_size = kPageSize4KiB;"""
    new="""  auto& guest=runtime.GetGuestMemory();
  constexpr u32 page_size=kPageSize4KiB;
  const u64 count=(u64{length}+page_size-1)/page_size;
  if (count && (!segments_address ||
      !guest.GetReadOnlySpan(segments_address,count*sizeof(be_u32)))) {
    if (out_bytes_read) *out_bytes_read=0;
    return X_STATUS_ACCESS_VIOLATION;
  }
  u32 segment_index=0;"""
    source=replace(source,old,new)
    old="""    u32 read_length = read_remain;
    u32 read_buffer = *segments;
    if (read_length > page_size) {
      read_length = page_size;
      segments++;
    }"""
    new="""    const u32 read_length=std::min(read_remain,page_size);
    const auto segment=guest.Load<be_u32>(segments_address+segment_index*sizeof(be_u32));
    if (!segment || !static_cast<u32>(*segment)) {
      result=X_STATUS_ACCESS_VIOLATION;
      break;
    }
    const u32 read_buffer=*segment;
    ++segment_index;"""
    source=replace(source,old,new)
    old="""        byte_offset ? ((byte_offset != ~u64{0} && byte_offset != ~u64{1}) ? byte_offset + read_total
                                                                          : byte_offset)
                    : -1,"""
    new="""        byte_offset==~u64{0} ? byte_offset : byte_offset+read_total,"""
    source=replace(source,old,new)
    source=replace(source,"    read_total += bytes_read;\n    read_remain -= read_length;",
        "    read_total += bytes_read;\n    if (bytes_read < read_length) break; // stop at a short read/EOF\n    read_remain -= read_length;")
    return source

def patch_file(source):
    source=replace(source,'#include <rex/kernel/title_runtime.h>',
                   '#include <rex/kernel/title_runtime.h>\n#include <rex/kernel/guest_memory.h>')
    source=replace(source,READ_CURSOR_OLD,READ_CURSOR_NEW)
    source=replace(source,WRITE_CURSOR_OLD,WRITE_CURSOR_NEW)
    source=replace(source,VIRTUAL_READ_OLD,VIRTUAL_READ_NEW)
    source=replace(source,"#include <span>","#include <span>\n#include <algorithm>\n#include <atomic>\n#include <cstdlib>\n#include <string_view>")
    source=replace(source,"namespace {\n\nvoid NotifyIOCompletionPorts","namespace {\n"+RESOURCE_TRACE+"\nvoid NotifyIOCompletionPorts")
    source=replace(source,"  if (out_bytes_read) {\n    *out_bytes_read = static_cast<u32>(bytes_read);",
        """  if (std::getenv("X360_METRO_BOOT") && IsMetroUIResource(file->GetInfo().name)) {
    static std::atomic_uint count{0};
    const auto n=count.fetch_add(1,std::memory_order_relaxed)+1;
    if(n<=96 || (n & (n-1))==0)
      REXSYS_INFO("METRO_UI_FILE name={} size={} offset={} requested={} actual={} status={:08X} count={}",
                  file->GetInfo().name,file->GetInfo().size,byte_offset,buffer_length,
                  bytes_read,static_cast<u32>(result),n);
  }
  if (out_bytes_read) {
    *out_bytes_read = static_cast<u32>(bytes_read);""")
    return patch_scatter(source)

NOTIFICATION_STUB = "REX_EXPORT_STUB(__imp__DrvGetContentStorageNotification);"
NOTIFICATION_ENTRY = """namespace rex::kernel::xboxkrnl {
u32 DrvGetContentStorageNotification_entry(u32 notification_address) {
  // Retail XAM treats any nonnegative return as a populated notification.
  // The hosted provider does not implement this stream. Do not return the
  // incoming r3 pointer or write an invented notification structure.
  return notification_address ? X_STATUS_NOT_SUPPORTED : X_STATUS_INVALID_PARAMETER;
}
}  // hosted storage notification namespace
REX_EXPORT(__imp__DrvGetContentStorageNotification,
           rex::kernel::xboxkrnl::DrvGetContentStorageNotification_entry)"""

def patch_storage_notifications(source):
    return replace(source, NOTIFICATION_STUB, NOTIFICATION_ENTRY)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    p.add_argument("--tests",type=Path,required=True)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    io=a.sdk/"src/kernel/xboxkrnl/xboxkrnl_io.cpp"
    hid=a.sdk/"src/kernel/xboxkrnl/xboxkrnl_hid.cpp"
    file=a.sdk/"src/kernel/object/file_object.cpp"
    test=a.sdk/"tests/unit/kernel/files_test.cpp"
    tests=a.tests.read_text()
    if "metro_io_runtime" in test.read_text():raise ValueError("test already installed")
    info=a.sdk/"src/kernel/xboxkrnl/xboxkrnl_io_info.cpp"
    outputs={io:patch_io(io.read_text()),file:patch_file(file.read_text()),
             info:patch_file_information(info.read_text()),
             hid:patch_storage_notifications(hid.read_text()),
             test:test.read_text()+"\n"+tests}
    for path,content in outputs.items():path.write_text(content)
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)

if __name__=="__main__":main()
