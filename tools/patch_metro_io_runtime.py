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
    if source.count(old)!=2:raise ValueError("unexpected offset use")
    return source.replace(old,"byte_offset")

def patch_file(source):
    source=replace(source,'#include <rex/kernel/title_runtime.h>',
                   '#include <rex/kernel/title_runtime.h>\n#include <rex/kernel/guest_memory.h>')
    source=replace(source,READ_CURSOR_OLD,READ_CURSOR_NEW)
    source=replace(source,WRITE_CURSOR_OLD,WRITE_CURSOR_NEW)
    return replace(source,VIRTUAL_READ_OLD,VIRTUAL_READ_NEW)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    p.add_argument("--tests",type=Path,required=True)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    io=a.sdk/"src/kernel/xboxkrnl/xboxkrnl_io.cpp"
    file=a.sdk/"src/kernel/object/file_object.cpp"
    test=a.sdk/"tests/unit/kernel/files_test.cpp"
    tests=a.tests.read_text()
    if "metro_io_runtime" in test.read_text():raise ValueError("test already installed")
    outputs={io:patch_io(io.read_text()),file:patch_file(file.read_text()),
             test:test.read_text()+"\n"+tests}
    for path,content in outputs.items():path.write_text(content)
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)

if __name__=="__main__":main()
