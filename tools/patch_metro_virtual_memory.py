#!/usr/bin/env python3
"""Restore guest virtual-memory contracts exercised by the original Metro heap."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

def replace(source, old, new):
    if source.count(old) != 1:
        raise ValueError("unexpected memory contract anchor: " + old[:100])
    return source.replace(old, new, 1)

HELPERS = r"""
// Retail XAM selects region 3 for a user-process heap at 8171F264-8171F280.
// Like the SDK's existing regions 0..2, this uses the hosted guest address
// space. No claim of independent console process address spaces is made.
bool ValidRangeInHeap(BaseHeap* heap, u32 base, u32 size) {
  return heap && size && base >= heap->GetHeapBase() &&
      u64{base} + size <= u64{heap->GetHeapBase()} + heap->GetHeapSize();
}

bool RoundGuestRange(u32 base, u64 size, u32 page, u32& rounded_base, u32& rounded_size) {
  if (!size || !page) return false;
  const u64 start = u64{base} - base % page;
  const u64 end = (u64{base} + size + page - 1) / page * page;
  if (end > 0x100000000ull || end <= start || end - start > 0xffffffffull)
    return false;
  rounded_base = static_cast<u32>(start);
  rounded_size = static_cast<u32>(end - start);
  return true;
}

X_STATUS CheckMemoryInOut(u32 base, u32 size, u32 old_protect = 0) {
  if (!base || !size) return X_STATUS_INVALID_PARAMETER;
  const auto overlaps = [](u32 a, u32 b) {
    return u64{a} < u64{b}+4 && u64{b} < u64{a}+4;
  };
  if (overlaps(base,size) || (old_protect &&
      (overlaps(base,old_protect) || overlaps(size,old_protect))))
    return X_STATUS_INVALID_PARAMETER;
  auto& guest = kernel::GetCurrent().GetGuestMemory();
  if (!guest.GetWritableSpan(base,4) || !guest.GetWritableSpan(size,4) ||
      (old_protect && !guest.GetWritableSpan(old_protect,4)))
    return X_STATUS_ACCESS_VIOLATION;
  return X_STATUS_SUCCESS;
}

// Log the actual API arguments and return code, not a synthetic heap result.
// Opt in only for the original graphical boot and never read unchecked output.
void MetroMemoryTrace(const char* call, u32 region, u32 base, u32 size,
                      u32 flags, u32 protection, u32 status) {
  if (!std::getenv("X360_METRO_BOOT")) return;
  auto* thread = ThreadState::Get();
  const u32 lr = thread ? static_cast<u32>(thread->GetContext()->lr) : 0;
  if (lr < 0x81600000 || lr >= 0x81A80000) return;
  REXKRNL_WARN("METRO_VM {} lr={:08x} region={} base={:08x} size={:08x} flags={:08x} protect={:08x} status={:08x}",
               call, lr, region, base, size, flags, protection, status);
}
"""

def patch_memory(source):
    source = replace(source, "#include <cstring>", "#include <cstring>\n#include <cstdlib>\n#include <vector>\n#include <rex/kernel/guest_memory.h>")
    source = replace(source, "constexpr u32 kMaxMemoryRegionType = 2;", "constexpr u32 kMaxMemoryRegionType = 3;")
    source = replace(source, "}  // namespace\n\nu32 ToXdkProtectFlags", HELPERS + "\n}  // namespace\n\nu32 ToXdkProtectFlags")
    source = replace(source, "Region types 0 to 2 all use the guest heap.", "Region types 0 to 3 use the hosted guest address space.")
    source = replace(source, "@param region_type Range 0 to 2.", "@param region_type Range 0 to 3.")
    start = source.index("u32 NtAllocateVirtualMemory_entry(")
    end = source.index("struct X_MEMORY_BASIC_INFORMATION", start)
    body = source[start:end]
    alloc_args = """  u32 input_base = base_addr_ptr ? static_cast<u32>(*base_addr_ptr) : 0;
  u32 input_size = region_size_ptr ? static_cast<u32>(*region_size_ptr) : 0;"""
    body = replace(body, alloc_args, """  if (auto status = CheckMemoryInOut(base_addr_ptr.GetGuestAddress(),
                                     region_size_ptr.GetGuestAddress()); status != X_STATUS_SUCCESS)
    return status;
  u32 input_base = *base_addr_ptr;
  u32 input_size = *region_size_ptr;""")
    body = replace(body, """  u32 adjusted_base = *base_addr_ptr - (*base_addr_ptr % page_size);
  // Titles can pass negative sizes.
  u32 adjusted_size = static_cast<i32>(*region_size_ptr) < 0
                          ? -static_cast<i32>(region_size_ptr.GetValue())
                          : region_size_ptr.GetValue();
  // Without a base address the allocation granularity is 64 KB, otherwise the heap page size.
  adjusted_size =
      rex::RoundUpNonZero(adjusted_size, adjusted_base ? page_size : kernel::kPageSize64KiB);""",
    """  u32 adjusted_base = 0, adjusted_size = 0;
  // Preserve the documented signed-size convention without INT_MIN overflow.
  const i64 signed_size = static_cast<i32>(input_size);
  const u64 requested = signed_size < 0 ? static_cast<u64>(-signed_size) : static_cast<u64>(signed_size);
  if (!RoundGuestRange(input_base, requested,
                       input_base ? page_size : kernel::kPageSize64KiB,
                       adjusted_base, adjusted_size))
    return X_STATUS_INVALID_PARAMETER;""")
    body = replace(body, """  kernel::HeapAllocation prev_alloc_info = {};
  bool was_committed = false;""", """  // Capture only newly committed subranges, so a mixed commit never clears
  // an existing heap header or leaks the previous contents of a decommitted page.
  struct ZeroRange { u32 address; u32 size; };
  std::vector<ZeroRange> zero_ranges;""")
    body = replace(body, """    was_committed = heap->QueryRegionInfo(adjusted_base, &prev_alloc_info) &&
                    (prev_alloc_info.state & kernel::kMemoryAllocationCommit) != 0;""", """    if (!ValidRangeInHeap(heap, adjusted_base, adjusted_size))
      return X_STATUS_INVALID_PARAMETER;
    if ((alloc_type & kXMemCommit) && !(alloc_type & kXMemNoZero)) {
      const u64 end = u64{adjusted_base} + adjusted_size;
      for (u64 page = adjusted_base; page < end; page += page_size) {
        kernel::HeapAllocation info{};
        if (!heap->QueryRegionInfo(static_cast<u32>(page), &info))
          return X_STATUS_INVALID_PARAMETER;
        if (!(info.state & kernel::kMemoryAllocationCommit)) {
          if (!zero_ranges.empty() &&
              u64{zero_ranges.back().address} + zero_ranges.back().size == page)
            zero_ranges.back().size += page_size;
          else
            zero_ranges.push_back({static_cast<u32>(page), page_size});
        }
      }
    }""")
    body = replace(body, """    heap->Alloc(adjusted_size, page_size, allocation_type, protect, top_down, &address);""", """    if (!heap || adjusted_size > heap->GetHeapSize()) return X_STATUS_NO_MEMORY;
    heap->Alloc(adjusted_size, page_size, allocation_type, protect, top_down, &address);
    if (address && (alloc_type & kXMemCommit) && !(alloc_type & kXMemNoZero))
      zero_ranges.push_back({address, adjusted_size});""")
    body = replace(body, """      if (!was_committed) {
        kernel::GetCurrentState().GetAddressSpace()->Zero(address, adjusted_size);
      }""", """      for (const auto& range : zero_ranges)
        kernel::GetCurrentState().GetAddressSpace()->Zero(range.address, range.size);""")
    body = replace(body, """  u32 adjusted_base = *base_addr_ptr - (*base_addr_ptr % heap->GetPageSize());
  u32 adjusted_size = rex::RoundUpNonZero(*region_size_ptr, heap->GetPageSize());""", """  u32 adjusted_base = 0, adjusted_size = 0;
  if (!RoundGuestRange(*base_addr_ptr, *region_size_ptr, heap->GetPageSize(),
                       adjusted_base, adjusted_size) ||
      !ValidRangeInHeap(heap, adjusted_base, adjusted_size))
    return X_STATUS_INVALID_PARAMETER;""")
    body = replace(body, "*old_protect = tmp_old_protect;", "*old_protect = ToXdkProtectFlags(tmp_old_protect);")
    body = replace(body, """                                 u32 protect_bits, MappedU32 old_protect, u32 region_type) {
  if (!IsValidMemoryRegionType""", """                                 u32 protect_bits, MappedU32 old_protect, u32 region_type) {
  if (auto status = CheckMemoryInOut(base_addr_ptr.GetGuestAddress(),
                                     region_size_ptr.GetGuestAddress(),old_protect.GetGuestAddress());
      status != X_STATUS_SUCCESS) return status;
  if (!IsValidMemoryRegionType""")
    body = replace(body, """                              u32 region_type) {
  if (!IsValidMemoryRegionType(region_type) || !IsValidFreeType(free_type))""", """                              u32 region_type) {
  if (auto status = CheckMemoryInOut(base_addr_ptr.GetGuestAddress(),
                                     region_size_ptr.GetGuestAddress()); status != X_STATUS_SUCCESS)
    return status;
  if (!IsValidMemoryRegionType(region_type) || !IsValidFreeType(free_type))""")
    body = replace(body, """    const u64 end = rex::RoundUpNonZero(u64{base_addr_value} + region_size_value, page_size);
    base_addr_value -= base_addr_value % page_size;
    region_size_value = static_cast<u32>(end - base_addr_value);""", """    if (!RoundGuestRange(base_addr_value, region_size_value, page_size,
                         base_addr_value, region_size_value) ||
        !ValidRangeInHeap(heap,base_addr_value,region_size_value))
      return X_STATUS_INVALID_PARAMETER;""")
    body = replace(body, """    if (region_size_value != 0) {
      u32 freed_base""", """    if (region_size_value != 0) {
      if (!ValidRangeInHeap(heap,base_addr_value,region_size_value))
        return X_STATUS_INVALID_PARAMETER;
      u32 freed_base""")
    source = source[:start] + body + source[end:]
    source = replace(source, """  switch (region_type) {
    case 0:
    case 1:
    case 2:
      break;
    default:
      return X_STATUS_INVALID_PARAMETER;
  }""", """  if (!IsValidMemoryRegionType(region_type)) return X_STATUS_INVALID_PARAMETER;
  if (!memory_basic_information_ptr.GetGuestAddress()) return X_STATUS_INVALID_PARAMETER;
  if (!kernel::GetCurrent().GetGuestMemory().GetWritableSpan(
          memory_basic_information_ptr.GetGuestAddress(),sizeof(X_MEMORY_BASIC_INFORMATION)))
    return X_STATUS_ACCESS_VIOLATION;""")
    # Trace at the real export boundary, preserving exact status and outputs.
    for name, signature, args, flags, protect in [
        ("NtAllocateVirtualMemory", "MappedU32 a, MappedU32 n, u32 flags, u32 protect, u32 region", "a,n,flags,protect,region", "flags", "protect"),
        ("NtProtectVirtualMemory", "MappedU32 a, MappedU32 n, u32 protect, MappedU32 old, u32 region", "a,n,protect,old,region", "0", "protect"),
        ("NtFreeVirtualMemory", "MappedU32 a, MappedU32 n, u32 flags, u32 region", "a,n,flags,region", "flags", "0"),
    ]:
        source = replace(source, "u32 "+name+"_entry(", "static u32 "+name+"_impl(")
        pos = source.index("struct X_MEMORY_BASIC_INFORMATION")
        wrapper = f"""u32 {name}_entry({signature}) {{
  auto& guest = kernel::GetCurrent().GetGuestMemory();
  auto base_before = guest.Load<be_u32>(a.GetGuestAddress());
  auto size_before = guest.Load<be_u32>(n.GetGuestAddress());
  const u32 status = {name}_impl({args});
  const auto base = status == X_STATUS_SUCCESS ? guest.Load<be_u32>(a.GetGuestAddress()) : base_before;
  const auto size = status == X_STATUS_SUCCESS ? guest.Load<be_u32>(n.GetGuestAddress()) : size_before;
  MetroMemoryTrace("{name}", region, base ? static_cast<u32>(*base) : 0,
                  size ? static_cast<u32>(*size) : 0, {flags}, {protect}, status);
  return status;
}}

"""
        source = source[:pos] + wrapper + source[pos:]
    source = replace(source,"u32 NtQueryVirtualMemory_entry(","static u32 NtQueryVirtualMemory_impl(")
    pos=source.index("/**\n * Allocates contiguous physical memory.")
    source=source[:pos]+"""u32 NtQueryVirtualMemory_entry(u32 base, GuestPtrT<X_MEMORY_BASIC_INFORMATION> info,
                               u32 region) {
  const u32 status = NtQueryVirtualMemory_impl(base,info,region);
  MetroMemoryTrace("NtQueryVirtualMemory",region,base,
                   status == X_STATUS_SUCCESS ? static_cast<u32>(info->region_size) : 0,
                   status == X_STATUS_SUCCESS ? static_cast<u32>(info->state) : 0,
                   status == X_STATUS_SUCCESS ? static_cast<u32>(info->protect) : 0,status);
  return status;
}

"""+source[pos:]
    return source

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    p.add_argument("--tests",type=Path,required=True)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    path=a.sdk/"src/kernel/xboxkrnl/xboxkrnl_memory.cpp"
    test=a.sdk/"tests/unit/kernel/memory_test.cpp"
    original=test.read_text()
    if "metro_vm" in original: raise ValueError("tests already installed")
    original=replace(original,"regions 0 to 2 use the guest heap","regions 0 to 3 use the guest heap")
    original=replace(original,"{0u, 1u, 2u}","{0u, 1u, 2u, 3u}")
    original=replace(original,"{3u, 0x100u, 0xFFFFFFFFu}","{4u, 0x100u, 0xFFFFFFFFu}")
    patched=patch_memory(path.read_text())
    path.write_text(patched)
    test.write_text(original+"\n"+a.tests.read_text())
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)

if __name__=="__main__":main()
