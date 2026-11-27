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
from patch_metro_public_verification import corrected as patch_public_verification, native_test as public_verification_test, corrected_signature_verifier, signature_native_tests

def replace(source, old, new):
    if source.count(old)!=1 or new in source:
        raise ValueError("unexpected I/O patch anchor: "+old[:80])
    return source.replace(old,new,1)

IO_HEADER = '#include <rex/kernel/title_runtime.h>'
IO_HEADER_NEW = IO_HEADER + '\n#include <rex/kernel/guest_memory.h>\n#include <cstring>\n#include <atomic>\n#include <cstdlib>\n#include <string_view>'
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
CREATE_END_NEW = r"""  if (std::getenv("X360_METRO_BOOT")) {
    const auto slash=target_path.find_last_of("/\\");
    const auto name=std::string_view(target_path).substr(slash==std::string::npos?0:slash+1);
    if(name.ends_with(".xtt") || name.ends_with(".XTT") ||
       name.ends_with(".xzp") || name.ends_with(".XZP") ||
       name.ends_with(".xur") || name.ends_with(".XUR")) {
      static std::atomic_uint count{0};
      const auto n=count.fetch_add(1,std::memory_order_relaxed)+1;
      if(n<=96 || (n&(n-1))==0)
        REXKRNL_INFO("METRO_UI_OPEN name={} status={:08X} handle={:08X} count={} share={:08X} options={:08X}",
                     name,static_cast<u32>(result),handle,n,share_access,create_options);
    }
  }
  if (status_address) {
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

OPEN_FILE_OLD = """u32 NtOpenFile_entry(MappedU32 handle_out, u32 desired_access,
                     GuestPtrT<X_OBJECT_ATTRIBUTES> object_attrs,
                     GuestPtrT<X_IO_STATUS_BLOCK> io_status_block, u32 open_options) {
  return NtCreateFile_entry(handle_out, desired_access, object_attrs, io_status_block, nullptr, 0,
                            0, std::to_underlying(filesystem::Disposition::kOpen), open_options);
}"""
OPEN_FILE_NEW = """u32 NtOpenFile_entry(MappedU32 handle_out, u32 desired_access,
                     GuestPtrT<X_OBJECT_ATTRIBUTES> object_attrs,
                     GuestPtrT<X_IO_STATUS_BLOCK> io_status_block, u32 share_access,
                     u32 open_options) {
  // Original PPC 922186D0: r7 is share access (1), r8 is open options (0x60).
  // Losing r8 turns a synchronous regular-file request into directory flags.
  return NtCreateFile_entry(handle_out, desired_access, object_attrs, io_status_block, nullptr, 0,
                            share_access, std::to_underlying(filesystem::Disposition::kOpen), open_options);
}"""

def patch_open_file(source):
    return replace(source,OPEN_FILE_OLD,OPEN_FILE_NEW)

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
    return replace(patch_open_file(source),DISMOUNT_OLD,DISMOUNT_NEW)

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

def patch_file_cursor(source):
    source=replace(source,'#include <rex/kernel/title_runtime.h>',
                   '#include <rex/kernel/title_runtime.h>\n#include <rex/kernel/guest_memory.h>')
    source=replace(source,READ_CURSOR_OLD,READ_CURSOR_NEW)
    source=replace(source,WRITE_CURSOR_OLD,WRITE_CURSOR_NEW)
    return replace(source,VIRTUAL_READ_OLD,VIRTUAL_READ_NEW)

def patch_file(source):
    source=patch_file_cursor(source)
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

# Preserve explicit writable child aliases for absolute and directory-relative opens.
RELATIVE_OPEN_OLD = """  return OpenFrom(&file->GetNode(), path, options);"""
RELATIVE_OPEN_NEW = """  // Explicit child aliases (such as the Metro Content and Cache mounts)
  // must work from an existing partition directory handle as well as from
  // absolute paths. Keep ordinary same-provider relative opens unchanged.
  std::lock_guard lock(mutex_);
  auto& root_node = file->GetNode();
  const auto absolute = string::utf8_canonicalize_guest_path(
      string::utf8_join_guest_paths(root_node.GetAbsolutePath(), path));
  if (root_node.IsDirectory() && StartsWithComponents(absolute, root_node.GetAbsolutePath()) &&
      FindLink(absolute)) {
    auto resolved = ResolveMount(absolute, false);
    if (resolved && resolved->provider != &root_node.GetProvider())
      return OpenFrom(nullptr, absolute, options);
  }
  return OpenFrom(&root_node, path, options);"""
CROSS_PROVIDER_CHILD_OLD = """    if (parent && parent->HasChildVanished(*node)) {"""
CROSS_PROVIDER_CHILD_NEW = """    // A linked mount root is not a child of the underlying provider.
    // Never ask the firmware provider to detach a node owned elsewhere.
    if (parent && &parent->GetProvider() == &node->GetProvider() &&
        parent->HasChildVanished(*node)) {"""
CROSS_PROVIDER_READONLY_OLD = """  if (wants_write && ((parent && parent->IsReadOnly()) || (node && node->IsReadOnly()))) {"""
CROSS_PROVIDER_READONLY_NEW = """  if (wants_write && ((parent && (!node || &parent->GetProvider() == &node->GetProvider()) &&
                       parent->IsReadOnly()) || (node && node->IsReadOnly()))) {"""

def patch_filesystem(source):
    source=replace(source,RELATIVE_OPEN_OLD,RELATIVE_OPEN_NEW)
    source=replace(source,CROSS_PROVIDER_CHILD_OLD,CROSS_PROVIDER_CHILD_NEW)
    source=replace(source,CROSS_PROVIDER_READONLY_OLD,CROSS_PROVIDER_READONLY_NEW)
    # Directly nested provider roots are already resolved by absolute opens;
    # relative opens must not lose them just because they are not links.
    source=replace(source,"StartsWithComponents(absolute, root_node.GetAbsolutePath()) &&\n      FindLink(absolute))","StartsWithComponents(absolute, root_node.GetAbsolutePath()))")
    source=replace(source,"  return Opened{std::make_unique<NodeFile>(*node, access, std::move(stream)), action};",
        "  return Opened{std::make_unique<NodeFile>(*node, access, std::move(stream), ChildMountEntries(*node)), action};")
    source=replace(source,"  return std::unique_ptr<IDirectory>(std::make_unique<NodeDirectory>(*node, pattern));",
        "  return std::unique_ptr<IDirectory>(std::make_unique<NodeDirectory>(*node, pattern, ChildMountEntries(*node)));")
    return replace(source,"Result<void> FileSystem::Mount(const MountEntry& entry) {",r"""std::vector<FileStat> FileSystem::ChildMountEntries(Node& directory) const {
  std::vector<FileStat> result;
  if (!directory.IsDirectory()) return result;
  // Called under the mount-table lock. Snapshot only direct child names
  // whose current resolution really leads to a different provider.
  const auto parent = directory.GetAbsolutePath();
  auto add = [&](std::string_view candidate) {
    if (candidate.size() <= parent.size() ||
        !StartsWithComponents(candidate, parent)) return;
    const auto base = string::utf8_find_base_guest_path(candidate);
    if (!string::utf8_equal_case(base, parent)) return;
    auto resolved = ResolveMount(candidate, false);
    if (!resolved || resolved->provider == &directory.GetProvider()) return;
    std::lock_guard target_lock(resolved->provider->GetMutex());
    Node* node = resolved->provider->Resolve(resolved->relative);
    if (!node || !node->IsDirectory()) return;
    auto entry = node->GetInfo();
    entry.name = std::string(string::utf8_find_name_from_guest_path(candidate));
    if (entry.name.empty() || std::ranges::any_of(result, [&](const auto& previous) {
          return string::utf8_equal_case(previous.name, entry.name);
        })) return;
    entry.path = string::utf8_join_guest_paths(directory.GetPath(), entry.name);
    entry.absolute_path = std::string(candidate);
    result.push_back(std::move(entry));
  };
  for (const auto& link : links_) add(link.first);
  for (const auto& provider : providers_) add(provider->GetMountPath());
  return result;
}

Result<void> FileSystem::Mount(const MountEntry& entry) {""")

def patch_filesystem_header(source):
    return replace(source,"  [[nodiscard]] Result<Node*> ResolveNode(std::string_view path) const;",
                   "  [[nodiscard]] Result<Node*> ResolveNode(std::string_view path) const;\n  [[nodiscard]] std::vector<FileStat> ChildMountEntries(Node& directory) const;")

def patch_node_file_header(source):
    source=replace(source,"#include <string_view>","#include <string_view>\n#include <vector>")
    source=replace(source,"NodeFile(Node& node, Access access, std::unique_ptr<NodeStream> stream);",
        "NodeFile(Node& node, Access access, std::unique_ptr<NodeStream> stream,\n           std::vector<FileStat> child_mounts = {});")
    source=replace(source,"  std::unique_ptr<NodeStream> stream_;",
        "  std::unique_ptr<NodeStream> stream_;\n  // Mount namespace snapshot taken when this handle was opened.\n  std::vector<FileStat> child_mounts_;")
    source=replace(source,"NodeDirectory(Node& node, std::string_view pattern);",
        "NodeDirectory(Node& node, std::string_view pattern, std::vector<FileStat> child_mounts = {});")
    source=replace(source,"  void Restart() override { index_ = 0; }\n  [[nodiscard]] u64 GetPosition() const override { return index_; }",
        "  void Restart() override { index_ = mount_index_ = 0; }\n  [[nodiscard]] u64 GetPosition() const override { return index_ + mount_index_; }")
    return replace(source,"  size_t index_ = 0;",
        "  size_t index_ = 0;\n  std::vector<FileStat> child_mounts_;\n  size_t mount_index_ = 0;")

def patch_node_file(source):
    source=replace(source,"#include <format>","#include <format>\n#include <algorithm>\n#include <utility>\n#include <rex/string/text.h>")
    source=replace(source,"NodeFile::NodeFile(Node& node, Access access, std::unique_ptr<NodeStream> stream)",
        "NodeFile::NodeFile(Node& node, Access access, std::unique_ptr<NodeStream> stream,\n                   std::vector<FileStat> child_mounts)")
    source=replace(source,"      stream_(std::move(stream)) {",
        "      stream_(std::move(stream)), child_mounts_(std::move(child_mounts)) {")
    source=replace(source,"std::make_unique<NodeDirectory>(*node_, pattern)",
        "std::make_unique<NodeDirectory>(*node_, pattern, child_mounts_)")
    source=replace(source,"NodeDirectory::NodeDirectory(Node& node, std::string_view pattern)\n    : provider_(node.GetProvider().shared_from_this()), node_(&node), matcher_(pattern) {",
        "NodeDirectory::NodeDirectory(Node& node, std::string_view pattern, std::vector<FileStat> child_mounts)\n    : provider_(node.GetProvider().shared_from_this()), node_(&node), matcher_(pattern),\n      child_mounts_(std::move(child_mounts)) {")
    return replace(source, r"""  Node* child = node_->IterateChildren(matcher_, &index_);
  if (!child) {
    return std::nullopt;
  }
  return child->GetInfo();""",r"""  while (Node* child = node_->IterateChildren(matcher_, &index_)) {
    auto info = child->GetInfo();
    // A physical name hidden by a mount alias is never returned twice.
    if (!std::ranges::any_of(child_mounts_, [&](const auto& mount) {
          return string::utf8_equal_case(mount.name, info.name);
        })) return info;
  }
  while (mount_index_ < child_mounts_.size()) {
    const auto& entry = child_mounts_[mount_index_++];
    if (matcher_.Match(entry.name)) return entry;
  }
  return std::nullopt;""")

STFS_OLD = r"""u32 StfsCreateDevice_entry([[maybe_unused]] MappedVoid device_object, [[maybe_unused]] u32 flags,
                           [[maybe_unused]] MappedU32 out_device) {
  REX_KERNEL_STUB("StfsCreateDevice");
  return X_STATUS_SUCCESS;
}

u32 StfsControlDevice_entry([[maybe_unused]] MappedVoid device_object, u32 ioctl,
                            [[maybe_unused]] MappedVoid input_buffer,
                            [[maybe_unused]] u32 input_length,
                            [[maybe_unused]] MappedVoid output_buffer,
                            [[maybe_unused]] u32 output_length) {
  REX_KERNEL_STUB("StfsControlDevice({:#x})", static_cast<u32>(ioctl));
  return X_STATUS_SUCCESS;
}"""
STFS_NEW = r"""u32 StfsCreateDevice_entry(u32 request, u32 request_bytes) {
  // Three original 17559 XAM callers pass the same 88-byte in/out request.
  // +72 and +76 are outputs consumed immediately after nonnegative status.
  // Until their exact device-object ownership is reconstructed, do not
  // return success with untouched outputs or invent a host device pointer.
  if (!request || request_bytes != 88) return X_STATUS_INVALID_PARAMETER;
  auto& memory = kernel::GetCurrent().GetGuestMemory();
  if (!memory.GetReadOnlySpan(request, request_bytes) ||
      !memory.GetWritableSpan(request, request_bytes)) return X_STATUS_ACCESS_VIOLATION;
  return X_STATUS_NOT_SUPPORTED;
}

u32 StfsControlDevice_entry(u32 device_object, u32 ioctl) {
  // Original command values 0..5 are verified, but their buffer/device
  // lifetime contracts are incomplete. Do not dereference unknown state.
  if (!device_object || ioctl > 5) return X_STATUS_INVALID_PARAMETER;
  return X_STATUS_NOT_SUPPORTED;
}"""

def patch_stfs_contract(source):
    return replace(source, STFS_OLD, STFS_NEW)

PROFILE_MOUNT_TEST = r'''
REX_TEST_CASE_METHOD(Fixture, "Metro explicit content mount supports relative opens",
                     "[metro_profile_mount]") {
  const auto firmware = GetTemp() / "firmware";
  const auto storage = GetTemp() / "storage";
  WriteHost(firmware / "dash.xex", "original");
  WriteHost(firmware / "Content" / "shadowed.bin", "never exposed");
  WriteHost(storage / "profile" / "fixture.bin", "local");
  auto& fs = GetFileSystem();
  REQUIRE(fs.Mount({"\\Device\\Harddisk0\\Partition1", ProviderType::kHostDirectory,
                    firmware, MountFlags::kNone, {}}));
  REQUIRE(fs.Mount({"\\Device\\MetroProfileContent", ProviderType::kHostDirectory,
                    storage, MountFlags::kWritable, {}}));
  REQUIRE(fs.Link("game:", "\\Device\\Harddisk0\\Partition1"));
  REQUIRE(fs.Link("\\Device\\Harddisk0\\Partition1\\Content",
                  "\\Device\\MetroProfileContent"));
  auto partition = Open("game:");
  auto absolute = Open("game:\\Content");
  CHECK(absolute.file->GetInfo().absolute_path == "\\Device\\MetroProfileContent");
  auto content = fs.OpenRelative(*partition.file, "Content", {});
  REQUIRE(content);
  auto file = fs.OpenRelative(*content->file, "profile\\fixture.bin", {});
  REQUIRE(file);
  CHECK(ReadText(*file->file) == "local");
  auto nested = fs.OpenRelative(*partition.file, "Content\\profile\\fixture.bin", {});
  REQUIRE(nested);
  CHECK(ReadText(*nested->file) == "local");
  auto created = fs.OpenRelative(*partition.file, "Content\\profile\\new.bin",
      {.disposition = Disposition::kCreate, .access = Access::kWriteAccess});
  REQUIRE(created);
  CHECK(std::filesystem::exists(storage / "profile" / "new.bin"));
  CHECK_FALSE(std::filesystem::exists(firmware / "Content" / "profile" / "new.bin"));
  CHECK_FALSE(fs.OpenRelative(*partition.file, "forbidden.bin",
      {.disposition = Disposition::kCreate, .access = Access::kWriteAccess}));
  CHECK(ReadText(*Open("game:\\dash.xex").file) == "original");
  CHECK_FALSE(fs.OpenRelative(*partition.file, "ContentOther\\fixture.bin", {}));
  // Directory enumeration must expose the actual Content alias, not just
  // make explicit opens work. Both the VFS and open-handle APIs are tested.
  auto check_listing = [](auto& listing) {
    REQUIRE(listing);
    auto entry = (*listing)->Next();
    REQUIRE(entry);
    CHECK(entry->name == "Content");
    CHECK(entry->absolute_path == "\\Device\\Harddisk0\\Partition1\\Content");
    CHECK(rex::HasFlags(entry->attributes, rex::filesystem::FileAttributes::kDirectory));
    CHECK_FALSE((*listing)->Next());
    (*listing)->Restart();
    CHECK((*listing)->GetPosition() == 0);
    REQUIRE((*listing)->Next());
    CHECK_FALSE((*listing)->Next());
  };
  auto handle_listing = partition.file->List("cOnT*");
  check_listing(handle_listing);
  auto path_listing = fs.List("game:", "Content");
  check_listing(path_listing);
  auto no_match = partition.file->List("ContentOther");
  REQUIRE(no_match);
  CHECK_FALSE((*no_match)->Next());
  // Shadowed physical directory must not duplicate the writable alias.
  auto fresh = Open("game:");
  auto all = fresh.file->List("");
  REQUIRE(all);
  unsigned count = 0;
  while (auto item = (*all)->Next()) if (item->name == "Content") ++count;
  CHECK(count == 1);
  CHECK_FALSE(fs.Open("game:\\Content\\shadowed.bin", {}));
  CHECK(ReadText(*Open("game:\\Content\\profile\\fixture.bin").file) == "local");
  // A real nested mount (not a symbolic link) must be discoverable from
  // its physical parent while preserving registration precedence.
  REQUIRE(fs.Mount({"\\Device\\Harddisk0", ProviderType::kNull, {},
                    MountFlags::kWritable, {"\\Partition0"}}));
  auto disk=Open("\\Device\\Harddisk0");
  auto parts=disk.file->List("Partition1");
  REQUIRE(parts);
  auto partition_entry=(*parts)->Next();
  REQUIRE(partition_entry);
  CHECK(partition_entry->name=="Partition1");
  CHECK_FALSE((*parts)->Next());
  auto relative_partition=fs.OpenRelative(*disk.file,"Partition1",{});
  REQUIRE(relative_partition);
  CHECK(relative_partition->file->GetInfo().absolute_path=="\\Device\\Harddisk0\\Partition1");
}
'''

# Bounded queries at the original storage/resource I/O boundary.
ATTR_QUERY_OLD = r"""  auto object_name = kernel::GetCurrentState().GetAddressSpace()->TranslateVirtual<X_ANSI_STRING*>(
      object_attrs->name_ptr);
  auto path_str =
      kernel::TranslateAnsiPath(kernel::GetCurrentState().GetAddressSpace(), object_name);
  REXKRNL_TRACE(
      "NtQueryFullAttributesFile "
      "path={}",
      path_str);

  Pinned<FileObject> root_file;
  // 0xFFFFFFFD is ObDosDevices.
  if (object_attrs->root_directory != 0xFFFFFFFD && object_attrs->root_directory != 0) {
    root_file = kernel::GetCurrent().GetObjectTable().Get<FileObject>(object_attrs->root_directory);
    if (!root_file) {
      return X_STATUS_INVALID_HANDLE;
    }
  }

  auto target_path = StripDosDevicePrefix(
      kernel::TranslateAnsiPath(kernel::GetCurrentState().GetAddressSpace(), object_name));

"""
ATTR_QUERY_NEW = r"""  auto& guest = kernel::GetCurrent().GetGuestMemory();
  const auto output = file_info.GetGuestAddress();
  if (!output || !guest.GetWritableSpan(output,sizeof(X_FILE_NETWORK_OPEN_INFORMATION)))
    return X_STATUS_ACCESS_VIOLATION;
  if (!object_attrs.GetGuestAddress()) return X_STATUS_INVALID_PARAMETER;
  const auto attributes = guest.Load<X_OBJECT_ATTRIBUTES>(object_attrs.GetGuestAddress());
  if (!attributes) return X_STATUS_ACCESS_VIOLATION;
  std::string target_path;
  if (const auto status=CheckedAnsiPath(attributes->name_ptr,target_path);
      status!=X_STATUS_SUCCESS) return status;
  Pinned<FileObject> root_file;
  if (attributes->root_directory!=0xFFFFFFFD && attributes->root_directory!=0) {
    root_file=kernel::GetCurrent().GetObjectTable().Get<FileObject>(attributes->root_directory);
    if (!root_file) return X_STATUS_INVALID_HANDLE;
  }

"""
DIRECTORY_QUERY_OLD = r"""  X_STATUS result = X_STATUS_UNSUCCESSFUL;
  u32 info = 0;

  auto file = kernel::GetCurrent().GetObjectTable().Get<FileObject>(file_handle);
  auto name = kernel::TranslateAnsiPath(kernel::GetCurrentState().GetAddressSpace(), file_name);

  if (!IsValidPath(name, PathUse::kPattern)) {
    return X_STATUS_INVALID_PARAMETER;
  }

"""
DIRECTORY_QUERY_NEW = r"""  auto& guest=kernel::GetCurrent().GetGuestMemory();
  const u32 output=file_info_ptr.GetGuestAddress();
  const u32 iosb=io_status_block.GetGuestAddress();
  if (!output || !guest.GetWritableSpan(output,length) ||
      (iosb && !guest.GetWritableSpan(iosb,sizeof(X_IO_STATUS_BLOCK))))
    return X_STATUS_ACCESS_VIOLATION;
  if (iosb && u64{output}<u64{iosb}+sizeof(X_IO_STATUS_BLOCK) &&
      u64{iosb}<u64{output}+length) return X_STATUS_INVALID_PARAMETER;
  auto event=kernel::GetCurrent().GetObjectTable().Get<EventObject>(event_handle);
  if (event_handle && !event) return X_STATUS_INVALID_HANDLE;
  if ((apc_routine & ~3u) && !KernelThread::GetCallingThread())
    return X_STATUS_INVALID_PARAMETER;
  std::string name;
  if (const u32 address=file_name.GetGuestAddress()) {
    const auto desc=guest.Load<X_ANSI_STRING>(address);
    if (!desc) return X_STATUS_ACCESS_VIOLATION;
    const u16 count=desc->length;
    if (count>static_cast<u16>(desc->maximum_length)) return X_STATUS_INVALID_PARAMETER;
    if (count) {
      if (!desc->pointer) return X_STATUS_ACCESS_VIOLATION;
      auto bytes=guest.GetReadOnlySpan(desc->pointer,count);
      if (!bytes) return X_STATUS_ACCESS_VIOLATION;
      name.assign(reinterpret_cast<const char*>(bytes->data()),bytes->size());
    }
  }
  if (name.find('\0')!=std::string::npos || name.find_first_of("\\/")!=std::string::npos ||
      !IsValidPath(name,PathUse::kPattern)) return X_STATUS_INVALID_PARAMETER;
  X_STATUS result=X_STATUS_UNSUCCESSFUL;
  u32 info=0;
  auto file=kernel::GetCurrent().GetObjectTable().Get<FileObject>(file_handle);

"""
DIRECTORY_COUNT_OLD = r"""      info = length;"""
DIRECTORY_COUNT_NEW = r"""      info = offsetof(X_FILE_DIRECTORY_INFORMATION,file_name) +
             static_cast<u32>(file_info_ptr->file_name_length);"""
VOLUME_QUERY_OLD = r"""  info_ptr.Zero(info_length);"""
VOLUME_QUERY_NEW = r"""  auto& guest=kernel::GetCurrent().GetGuestMemory();
  const u32 output=info_ptr.GetGuestAddress(), iosb=io_status_block.GetGuestAddress();
  if (!output || !guest.GetWritableSpan(output,info_length) ||
      (iosb && !guest.GetWritableSpan(iosb,sizeof(X_IO_STATUS_BLOCK))))
    return X_STATUS_ACCESS_VIOLATION;
  if (iosb && u64{output}<u64{iosb}+sizeof(X_IO_STATUS_BLOCK) &&
      u64{iosb}<u64{output}+info_length) return X_STATUS_INVALID_PARAMETER;
  info_ptr.Zero(minimum_length);"""
DIRECTORY_OBJECT_OLD = r"""  REX_ASSERT(out_info != nullptr);

  std::optional<filesystem::FileStat> entry;"""
DIRECTORY_OBJECT_NEW = r"""  if (!out_info) return X_STATUS_ACCESS_VIOLATION;
  if (length<offsetof(X_FILE_DIRECTORY_INFORMATION,file_name))
    return X_STATUS_INFO_LENGTH_MISMATCH;
  if (!HasFlags(file->GetInfo().attributes,filesystem::FileAttributes::kDirectory))
    return X_STATUS_NOT_A_DIRECTORY;

  std::optional<filesystem::FileStat> entry;"""
DIRECTORY_OVERFLOW_OLD = r"""  auto end = reinterpret_cast<u8*>(out_info) + length;
  const std::string& entry_name = entry->name;
  if (reinterpret_cast<u8*>(&out_info->file_name[0]) + entry_name.size() > end) {
    REX_ASSERT_ALWAYS("Buffer overflow?");
    return X_STATUS_BUFFER_OVERFLOW;
  }"""
DIRECTORY_OVERFLOW_NEW = r"""  const std::string& entry_name=entry->name;
  if (entry_name.size()>length-offsetof(X_FILE_DIRECTORY_INFORMATION,file_name)) {
    pending_directory_entry=std::move(entry);
    return X_STATUS_BUFFER_OVERFLOW;
  }"""
DIRECTORY_RETRY_OLD = r"""    } else if (restart) {
      find->Restart();
    }
    entry = FindNext();"""
DIRECTORY_RETRY_NEW = r"""    } else if (restart) {
      pending_directory_entry.reset();
      find->Restart();
    }
    if (pending_directory_entry) {
      entry=std::move(pending_directory_entry);
      pending_directory_entry.reset();
    } else {
      entry=FindNext();
    }"""
DIRECTORY_PATTERN_OLD = r"""    REX_ASSERT(rex::string::utf8_find_any_of(file_name, "\\") == std::string_view::npos);"""
DIRECTORY_PATTERN_NEW = r"""    if (file_name.find_first_of("\\/")!=std::string_view::npos)
      return X_STATUS_INVALID_PARAMETER;"""
DIRECTORY_SET_FIND_OLD = r"""void FileObject::SetFindPattern(std::string_view pattern) {
"""
DIRECTORY_SET_FIND_NEW = r"""void FileObject::SetFindPattern(std::string_view pattern) {
  pending_directory_entry.reset();
"""
DIRECTORY_HEADER_OLD = r"""  PropagateConst<std::unique_ptr<filesystem::IDirectory>> find;"""
DIRECTORY_HEADER_NEW = r"""  PropagateConst<std::unique_ptr<filesystem::IDirectory>> find;
  std::optional<filesystem::FileStat> pending_directory_entry;"""

def patch_storage_queries(source):
    for old,new in ((ATTR_QUERY_OLD,ATTR_QUERY_NEW),
                    (DIRECTORY_QUERY_OLD,DIRECTORY_QUERY_NEW),
                    (DIRECTORY_COUNT_OLD,DIRECTORY_COUNT_NEW)):
        source=replace(source,old,new)
    return source

def patch_volume_query(source):
    start=source.index("u32 NtQueryVolumeInformationFile_entry(")
    return source[:start]+replace(source[start:],VOLUME_QUERY_OLD,VOLUME_QUERY_NEW)

def patch_directory_object(source):
    for old,new in ((DIRECTORY_OBJECT_OLD,DIRECTORY_OBJECT_NEW),
                    (DIRECTORY_OVERFLOW_OLD,DIRECTORY_OVERFLOW_NEW),
                    (DIRECTORY_RETRY_OLD,DIRECTORY_RETRY_NEW),
                    (DIRECTORY_PATTERN_OLD,DIRECTORY_PATTERN_NEW),
                    (DIRECTORY_SET_FIND_OLD,DIRECTORY_SET_FIND_NEW)):
        source=replace(source,old,new)
    return source

def patch_directory_header(source):
    source=replace(source,"#include <rex/platform.h>",
                   "#include <rex/filesystem/file_stat.h>\\n#include <rex/platform.h>".replace("\\n","\n"))
    return replace(source,DIRECTORY_HEADER_OLD,DIRECTORY_HEADER_NEW)

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
    tests=a.tests.read_text()+"\n"+public_verification_test()+"\n"+signature_native_tests()
    if "metro_io_runtime" in test.read_text():raise ValueError("test already installed")
    info=a.sdk/"src/kernel/xboxkrnl/xboxkrnl_io_info.cpp"
    filesystem=a.sdk/"src/filesystem/file_system.cpp"
    filesystem_test=a.sdk/"tests/unit/filesystem/file_system_test.cpp"
    filesystem_header=a.sdk/"src/filesystem/file_system.h"
    node_file=a.sdk/"src/filesystem/node_file.cpp"
    node_header=a.sdk/"src/filesystem/node_file.h"
    file_header=a.sdk/"include/rex/kernel/object/file_object.h"
    crypt=a.sdk/"src/kernel/xboxkrnl/xboxkrnl_crypt.cpp"
    outputs={crypt:corrected_signature_verifier(patch_public_verification(crypt.read_text())),
             file_header:patch_directory_header(file_header.read_text()),
             filesystem:patch_filesystem(filesystem.read_text()),
             filesystem_header:patch_filesystem_header(filesystem_header.read_text()),
             node_file:patch_node_file(node_file.read_text()),
             node_header:patch_node_file_header(node_header.read_text()),
             filesystem_test:filesystem_test.read_text()+"\n"+PROFILE_MOUNT_TEST,
             io:patch_stfs_contract(patch_storage_queries(patch_io(io.read_text()))),
             file:patch_directory_object(patch_file(file.read_text())),
             info:patch_volume_query(patch_file_information(info.read_text())),
             hid:patch_storage_notifications(hid.read_text()),
             test:test.read_text()+"\n"+tests}
    for path,content in outputs.items():path.write_text(content)
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)

if __name__=="__main__":main()
