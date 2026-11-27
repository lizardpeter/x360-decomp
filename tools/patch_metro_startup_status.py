#!/usr/bin/env python3
"""Implement the hosted startup status contracts without fabricated output."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

OLD="REX_EXPORT_STUB(__imp__EtxProducerRegister);"
NEW="REX_EXPORT_STUB_RETURN(__imp__EtxProducerRegister, rex::kernel::X_STATUS_NOT_SUPPORTED);"

def patch_status(source):
    if source.count(OLD)!=1 or NEW in source:
        raise ValueError("unexpected producer registration stub")
    return source.replace(OLD,NEW)


def trace_export(source,symbol):
    anchor=f"REX_EXPORT(__imp__{symbol}, rex::kernel::xboxkrnl::{symbol}_entry)"
    if source.count(anchor)!=1:raise ValueError("unexpected trace anchor "+symbol)
    return source.replace(anchor,f"""REX_HOOK_RAW(__imp__{symbol}) {{
  const auto lr=static_cast<::rex::u32>(ctx.lr);
  const auto r3=ctx.r3.u32, r4=ctx.r4.u32, r5=ctx.r5.u32, r6=ctx.r6.u32, r7=ctx.r7.u32;
  ::rex::ppc::GuestToHostThunk<rex::kernel::xboxkrnl::{symbol}_entry>(ctx,base);
  if ((lr>=0x815F0000u && lr<0x81C00000u) ||
      (lr>=0x92000000u && lr<0x93028000u)) {{
    static std::atomic_uint count{{0}};
    const auto n=count.fetch_add(1,std::memory_order_relaxed)+1;
    if (n<=8 || (n & (n-1))==0)
      REXCPU_WARN("METRO_CONTRACT name={symbol} lr=0x{{:08X}} args={{:08X}},{{:08X}},{{:08X}},{{:08X}},{{:08X}} result=0x{{:08X}} count={{}}",
                  lr,r3,r4,r5,r6,r7,ctx.r3.u32,n);
  }}
}}""",1)

def patch_object_contracts(source):
    anchor="#include <rex/kernel/title_runtime.h>"
    if source.count(anchor)!=1:raise ValueError("object memory header")
    source=source.replace(anchor,anchor+"\n#include <rex/kernel/guest_memory.h>",1)
    for symbol in ("ObCreateObject","ObInsertObject"):
        anchor=f"REX_EXPORT_STUB(__imp__{symbol});"
        if source.count(anchor)!=1:raise ValueError("object stub anchor "+symbol)
        source=source.replace(anchor,f"REX_EXPORT_STUB_RETURN(__imp__{symbol}, rex::kernel::X_STATUS_NOT_SUPPORTED);",1)
    for signature,arg in (
        ("u32 ObLookupThreadByThreadId_entry(u32 thread_id, MappedU32 out_object_ptr) {","out_object_ptr"),
        ("u32 ObReferenceObjectByHandle_entry(u32 handle, u32 object_type_ptr, MappedU32 out_object_ptr) {","out_object_ptr"),
        ("u32 ObOpenObjectByPointer_entry(MappedVoid object_ptr, MappedU32 out_handle_ptr) {","out_handle_ptr"),
    ):
        if source.count(signature)!=1:raise ValueError("object output anchor")
        condition=(f"{arg}.GetGuestAddress() && " if "ReferenceObjectByHandle" in signature else
                   f"!{arg}.GetGuestAddress() || ")
        source=source.replace(signature,signature+f"""
  if ({condition}!kernel::GetCurrent().GetGuestMemory().GetWritableSpan(
        {arg}.GetGuestAddress(),sizeof(be_u32)))
    return X_STATUS_ACCESS_VIOLATION;
""",1)
    # Confirmed by original XAM at 8167AB34..8167AB54 and 8167ABC4..8167ABE4.
    for old,new in (
        (r'''u32 ObReferenceObjectByName_entry(MappedString name, [[maybe_unused]] u32 attributes,''', r'''u32 ObReferenceObjectByName_entry(GuestPtrT<X_ANSI_STRING> name, [[maybe_unused]] u32 attributes,'''),
        (r'''  auto& table = kernel::GetCurrent().GetObjectTable();
  auto opened = table.OpenByName(name.GetValue());''', r'''  // Retail callers pass PANSI_STRING, not a NUL-terminated char pointer.
  auto& runtime = kernel::GetCurrent();
  auto& guest = runtime.GetGuestMemory();
  if (!out_object_ptr.GetGuestAddress() ||
      !guest.GetWritableSpan(out_object_ptr.GetGuestAddress(), sizeof(be_u32)))
    return X_STATUS_ACCESS_VIOLATION;
  if (!name.GetGuestAddress()) return X_STATUS_INVALID_PARAMETER;
  auto descriptor = guest.Load<X_ANSI_STRING>(name.GetGuestAddress());
  if (!descriptor) return X_STATUS_ACCESS_VIOLATION;
  const u16 length = descriptor->length;
  if (!length || length > static_cast<u16>(descriptor->maximum_length))
    return X_STATUS_OBJECT_NAME_INVALID;
  if (!descriptor->pointer) return X_STATUS_ACCESS_VIOLATION;
  auto bytes = guest.GetReadOnlySpan(descriptor->pointer, length);
  if (!bytes) return X_STATUS_ACCESS_VIOLATION;
  std::string object_name(reinterpret_cast<const char*>(bytes->data()), bytes->size());
  if (object_name.find('\0') != std::string::npos) return X_STATUS_OBJECT_NAME_INVALID;
  auto& table = runtime.GetObjectTable();
  auto opened = table.OpenByName(object_name);'''),
        (r'''    REXKRNL_WARN_ONCE(bodyless_once, std::to_underlying(object.GetType()),
                      "ObReferenceObjectByHandle on object type {} with no guest body returns 0",
                      std::to_underlying(object.GetType()));''', r'''    REXKRNL_WARN_ONCE(bodyless_once, std::to_underlying(object.GetType()),
                      "ObReferenceObjectByHandle on object type {} has no guest body",
                      std::to_underlying(object.GetType()));
    return X_STATUS_NOT_SUPPORTED;'''),
    ):
        if source.count(old)!=1:raise ValueError("named reference ABI anchor")
        source=source.replace(old,new,1)
    for name in ("ObDereferenceObject","ObReferenceObjectByHandle","ObReferenceObjectByName","ObOpenObjectByPointer","ObLookupThreadByThreadId"):
        source=trace_export(source,name)
    anchor='    REXKRNL_WARN("ObDereferenceObject: {:#x} is not a registered object", native_ptr);'
    if source.count(anchor)!=1:raise ValueError("invalid release trace")
    source=source.replace(anchor,'''    static std::atomic_uint invalid_releases{0};
    const auto n=invalid_releases.fetch_add(1,std::memory_order_relaxed)+1;
    if (n<=8 || (n & (n-1))==0)
      REXKRNL_WARN("ObDereferenceObject: {:#x} is not a registered object (count={})", native_ptr,n);''',1)
    return source

def patch_io_trace(source):
    old=r'''  REX_KERNEL_STUB("IoSynchronousDeviceIoControlRequest({:#x})", static_cast<u32>(ioctl));
  return X_STATUS_SUCCESS;'''
    new=r'''  // A hosted file or dispatcher object is not an optical device provider.
  // Do not signal success or populate unspecified response data.
  REXKRNL_TRACE("Hosted device control without provider: {:#x}", ioctl);
  if (!device_object.GetGuestAddress() ||
      !kernel::GetCurrent().GetObjectTable().GetByAddress(device_object.GetGuestAddress()))
    return X_STATUS_INVALID_HANDLE;
  return X_STATUS_NOT_SUPPORTED;'''
    if source.count(old)!=1:raise ValueError("synchronous device control anchor")
    source=source.replace(old,new,1)
    for name in ("IoDismountVolumeByName","NtQueryFullAttributesFile","NtOpenFile","NtCreateFile"):
        source=trace_export(source,name)
    return source

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    p.add_argument("--tests",type=Path,required=True)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    source=a.sdk/"src/kernel/xboxkrnl/xboxkrnl_stub.cpp"
    tests=a.sdk/"tests/unit/kernel/xam_input_test.cpp"
    old=tests.read_text()
    if "metro_startup_status" in old:raise ValueError("tests already installed")
    replacements={
        source:patch_status(source.read_text()),
    }
    # Original XAM treats these as value-returning APIs, not NTSTATUS.
    # This hosted runtime has no persisted console raw dump or Argon
    # hardware-error record. Never populate unknown output layouts.
    for filename,symbol in (
        ("xboxkrnl_debug.cpp","DumpGetRawDumpInfo"),
        ("xboxkrnl_hal.cpp","HalGetNotedArgonErrors"),
    ):
        path=source.parent/filename
        original=path.read_text()
        anchor=f"REX_EXPORT_STUB(__imp__{symbol});"
        if original.count(anchor)!=1:raise ValueError(f"unexpected {symbol} stub")
        replacements[path]=original.replace(anchor,f"REX_EXPORT_STUB_RETURN(__imp__{symbol}, 0);")
    ob=source.parent/"xboxkrnl_ob.cpp"
    io=source.parent/"xboxkrnl_io.cpp"
    replacements[ob]=patch_object_contracts(ob.read_text())
    replacements[io]=patch_io_trace(io.read_text())
    for path,updated in replacements.items():
        path.write_text(updated)
    tests.write_text(old+"\n"+a.tests.read_text())
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
if __name__=="__main__":main()
