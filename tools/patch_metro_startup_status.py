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

CUSTOM_OBJECT_EDITS = {
  "include/rex/kernel/object/kernel_object.h": [
    [
      "#include <atomic>",
      "#include <atomic>\n#include <functional>"
    ],
    [
      "  bool owns_guest_block = false;",
      "  u32 guest_object_type = 0;\n  bool guest_creation_pending = false;\n  bool guest_published = false;\n  std::function<void(bool)> guest_cleanup;\n  bool owns_guest_block = false;"
    ]
  ],
  "include/rex/kernel/object/object_table.h": [
    [
      "  /** Pins every `KernelObject`, once per `KernelObject`. */",
      "  // Register a body owned by an original guest allocator, initially without a handle.\n  [[nodiscard]] virtual Result<void> AddGuestObject(std::unique_ptr<KernelObject> object,\n                                                    u32 body_address) = 0;\n  [[nodiscard]] virtual Result<X_HANDLE> InsertGuestObject(const ObjectPin& object) = 0;\n\n  /** Pins every `KernelObject`, once per `KernelObject`. */"
    ]
  ],
  "src/kernel/object_table.h": [
    [
      "  ObjectPin GetByAddress(u32 address) override;",
      "  [[nodiscard]] Result<void> AddGuestObject(std::unique_ptr<KernelObject> object,\n                                            u32 body_address) override;\n  [[nodiscard]] Result<X_HANDLE> InsertGuestObject(const ObjectPin& object) override;\n  ObjectPin GetByAddress(u32 address) override;"
    ],
    [
      "  X_HANDLE AddSlot(KernelObject* object);",
      "  X_HANDLE AddSlot(KernelObject* object);\n  void SyncGuestCounts(KernelObject* object);"
    ]
  ],
  "src/kernel/object_table.cpp": [
    [
      "KernelObject::~KernelObject() {\n  if (owns_guest_block",
      "KernelObject::~KernelObject() {\n  if (guest_cleanup)\n    log::NoThrow(log::system, [this] { guest_cleanup(guest_published); });\n  if (owns_guest_block"
    ],
    [
      "    for (auto& [raw, owned] : objects_) {\n      retired.push_back(owned.release());",
      "    for (auto& [raw, owned] : objects_) {\n      raw->guest_published = false; // no delete callbacks during bulk teardown\n      retired.push_back(owned.release());"
    ],
    [
      "X_HANDLE ObjectTable::AddSlot(KernelObject* object) {",
      "void ObjectTable::SyncGuestCounts(KernelObject* object) {\n  if (!object->guest_object_type || !memory_) return;\n  auto* header = memory_->TranslateVirtual<X_OBJECT_HEADER*>(\n      object->guest_ptr - static_cast<u32>(sizeof(X_OBJECT_HEADER)));\n  header->pointer_count = object->pointer_refs + static_cast<u32>(object->handles.size());\n  header->handle_count = static_cast<u32>(object->handles.size());\n}\n\nX_HANDLE ObjectTable::AddSlot(KernelObject* object) {"
    ],
    [
      "  object->handles.push_back(handle);\n  return handle;",
      "  object->handles.push_back(handle);\n  SyncGuestCounts(object);\n  return handle;"
    ],
    [
      "Result<X_HANDLE> ObjectTable::AddEvent(bool manual_reset, bool initial_state) {",
      "Result<void> ObjectTable::AddGuestObject(std::unique_ptr<KernelObject> object,\n                                         u32 body_address) {\n  if (!object || !object->guest_object_type || !body_address || !object->guest_cleanup)\n    return Err(StatusError(X_STATUS_INVALID_PARAMETER));\n  std::unique_lock lock(mutex_);\n  if (block_objects_.contains(body_address))\n    return Err(StatusError(X_STATUS_OBJECT_NAME_COLLISION));\n  object->pointer_refs = 1;\n  object->guest_creation_pending = true;\n  KernelObject* raw = Register(std::move(object), AddOptions{{}, ObjectBlock{body_address}});\n  raw->guest_published = true;\n  SyncGuestCounts(raw);\n  return Ok();\n}\n\nResult<X_HANDLE> ObjectTable::InsertGuestObject(const ObjectPin& object) {\n  if (!object) return Err<X_HANDLE>(StatusError(X_STATUS_INVALID_HANDLE));\n  std::unique_lock lock(mutex_);\n  KernelObject* raw = &object.GetKernelObject();\n  if (!objects_.contains(raw) || !raw->guest_object_type ||\n      !raw->guest_creation_pending || !raw->pointer_refs)\n    return Err<X_HANDLE>(StatusError(X_STATUS_INVALID_HANDLE));\n  const auto handle = AddSlot(raw);\n  --raw->pointer_refs;\n  raw->guest_creation_pending = false;\n  SyncGuestCounts(raw);\n  return handle;\n}\n\nResult<X_HANDLE> ObjectTable::AddEvent(bool manual_reset, bool initial_state) {"
    ],
    [
      "  std::erase(object->handles, handle);",
      "  std::erase(object->handles, handle);\n  SyncGuestCounts(object);"
    ],
    [
      "  ++raw->pointer_refs;\n  return Ok();",
      "  ++raw->pointer_refs;\n  SyncGuestCounts(raw);\n  return Ok();"
    ],
    [
      "    --raw->pointer_refs;\n    retired = Settle(raw);",
      "    --raw->pointer_refs;\n    SyncGuestCounts(raw);\n    retired = Settle(raw);"
    ]
  ],
  "src/kernel/xboxkrnl/xboxkrnl_ob.cpp": [
    [
      "#include <utility>",
      "#include <utility>\n#include <cstring>\n#include <rex/kernel/function_dispatcher.h>"
    ],
    [
      "u32 ObOpenObjectByPointer_entry(MappedVoid object_ptr, MappedU32 out_handle_ptr) {",
      "u32 ObCreateObject_entry(u32 type_address, u32 attributes, u32 size, MappedU32 output) {\n  auto& runtime = kernel::GetCurrent();\n  auto& memory = runtime.GetGuestMemory();\n  const u32 out = output.GetGuestAddress();\n  if (!out || !memory.GetWritableSpan(out, sizeof(be_u32))) return X_STATUS_ACCESS_VIOLATION;\n  if (attributes) return X_STATUS_NOT_SUPPORTED;\n  if (!type_address || !size || size > 0xffffffffu - sizeof(X_OBJECT_HEADER))\n    return X_STATUS_INVALID_PARAMETER;\n  auto descriptor = memory.Load<X_OBJECT_TYPE>(type_address);\n  if (!descriptor) return X_STATUS_ACCESS_VIOLATION;\n  const u32 alloc = descriptor->constructor, release = descriptor->destructor;\n  const u32 cleanup = descriptor->unk_0c;\n  if (!alloc || !release || descriptor->unk_08 || descriptor->unk_10)\n    return X_STATUS_NOT_SUPPORTED;\n  auto* current = KernelThread::GetCallingThread();\n  auto* dispatcher = kernel::GetCurrentState().GetFunctionDispatcher();\n  if (!current || !dispatcher || !dispatcher->GetFunction(alloc) ||\n      !dispatcher->GetFunction(release) || (cleanup && !dispatcher->GetFunction(cleanup)))\n    return X_STATUS_PROCEDURE_NOT_FOUND;\n  const u32 total = size + static_cast<u32>(sizeof(X_OBJECT_HEADER));\n  u64 args[] = {total, static_cast<u32>(descriptor->pool_tag), 0};\n  const u32 block = static_cast<u32>(dispatcher->Execute(current->GetThreadState(), alloc, args, 3));\n  if (!block || block == 0xDEADBABEu) return X_STATUS_NO_MEMORY;\n  auto free_block = [&] {\n    u64 free_args[] = {block};\n    dispatcher->Execute(current->GetThreadState(), release, free_args, 1);\n  };\n  auto bytes = memory.GetWritableSpan(block, total);\n  if (!bytes || u64{block} + total > 0x100000000ull) {\n    free_block();\n    return X_STATUS_ACCESS_VIOLATION;\n  }\n  const u32 body = block + static_cast<u32>(sizeof(X_OBJECT_HEADER));\n  if (runtime.GetObjectTable().GetByAddress(body)) return X_STATUS_OBJECT_NAME_COLLISION;\n  std::memset(bytes->data(), 0, bytes->size());\n  X_OBJECT_HEADER header{};\n  header.pointer_count = 1;\n  header.object_type_ptr = type_address;\n  if (!memory.Store(block, header)) {\n    free_block();\n    return X_STATUS_ACCESS_VIOLATION;\n  }\n  auto object = std::make_unique<KernelObject>(std::in_place_type<XAMObject>,\n                                               std::unique_ptr<IXAMObject>{});\n  object->guest_object_type = type_address;\n  object->guest_cleanup = [owner=&runtime, block, body, cleanup, release](bool published) {\n    auto* caller = KernelThread::GetCallingThread();\n    if (!caller || &caller->GetRuntime() != owner) {\n      REXKRNL_WARN(\"Custom object {:08X} retired outside guest context\", body);\n      return;\n    }\n    auto* dispatch = kernel::GetCurrentState().GetFunctionDispatcher();\n    if (!dispatch || !dispatch->GetFunction(release)) return;\n    if (published && cleanup) {\n      if (!dispatch->GetFunction(cleanup)) return;\n      u64 delete_args[] = {body};\n      dispatch->Execute(caller->GetThreadState(), cleanup, delete_args, 1);\n    }\n    u64 release_args[] = {block};\n    dispatch->Execute(caller->GetThreadState(), release, release_args, 1);\n  };\n  auto& table = runtime.GetObjectTable();\n  auto added = table.AddGuestObject(std::move(object), body);\n  if (!added) return ToXStatus(added);\n  if (!memory.Store(out, be_u32{body})) {\n    auto pin = table.GetByAddress(body);\n    if (pin) (void)table.Dereference(pin);\n    return X_STATUS_ACCESS_VIOLATION;\n  }\n  REXKRNL_TRACE(\"Custom object type={:08X} body={:08X} size={}\", type_address, body, size);\n  return X_STATUS_SUCCESS;\n}\n\nu32 ObInsertObject_entry(u32 body, u32 attributes, u32 bias, MappedU32 output) {\n  auto& runtime = kernel::GetCurrent();\n  const u32 out = output.GetGuestAddress();\n  if (!out || !runtime.GetGuestMemory().GetWritableSpan(out, sizeof(be_u32)))\n    return X_STATUS_ACCESS_VIOLATION;\n  if (attributes || bias) return X_STATUS_NOT_SUPPORTED;\n  auto& table = runtime.GetObjectTable();\n  auto object = table.GetByAddress(body);\n  if (!object || !object.GetKernelObject().guest_object_type) return X_STATUS_INVALID_HANDLE;\n  auto inserted = table.InsertGuestObject(object);\n  if (!inserted) return ToXStatus(inserted);\n  *output = *inserted;\n  return X_STATUS_SUCCESS;\n}\n\nu32 ObOpenObjectByPointer_entry(MappedVoid object_ptr, MappedU32 out_handle_ptr) {"
    ],
    [
      "  auto object = table.ResolveObject(object_ptr.GetGuestAddress(), -1);",
      "  auto object = table.GetByAddress(object_ptr.GetGuestAddress());\n  if (!object) {\n    if (!object_ptr.GetGuestAddress() ||\n        !kernel::GetCurrent().GetGuestMemory().GetReadOnlySpan(\n            object_ptr.GetGuestAddress(), sizeof(X_DISPATCH_HEADER)))\n      return X_STATUS_ACCESS_VIOLATION;\n    object = table.ResolveObject(object_ptr.GetGuestAddress(), -1);\n  }"
    ],
    [
      "    const u32 expected_type = kernel::GetCurrentState().GetObjectTypeAddress(object.GetType());",
      "    const u32 expected_type = object.GetKernelObject().guest_object_type\n        ? object.GetKernelObject().guest_object_type\n        : kernel::GetCurrentState().GetObjectTypeAddress(object.GetType());"
    ],
    [
      "REX_EXPORT_STUB(__imp__ObCreateObject);",
      "REX_EXPORT(__imp__ObCreateObject, rex::kernel::xboxkrnl::ObCreateObject_entry)"
    ],
    [
      "REX_EXPORT_STUB(__imp__ObInsertObject);",
      "REX_EXPORT(__imp__ObInsertObject, rex::kernel::xboxkrnl::ObInsertObject_entry)"
    ]
  ]
}

def patch_guest_objects(path, source):
    for old, new in CUSTOM_OBJECT_EDITS[path]:
        if source.count(old)!=1:raise ValueError('guest object anchor: '+path+' '+old[:80])
        source=source.replace(old,new,1)
    return source

def patch_object_contracts(source):
    source=patch_guest_objects('src/kernel/xboxkrnl/xboxkrnl_ob.cpp',source)
    anchor="#include <rex/kernel/title_runtime.h>"
    if source.count(anchor)!=1:raise ValueError("object memory header")
    source=source.replace(anchor,anchor+"\n#include <rex/kernel/guest_memory.h>",1)
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
    for name in ("ObCreateObject","ObInsertObject","ObDereferenceObject","ObReferenceObjectByHandle","ObReferenceObjectByName","ObOpenObjectByPointer","ObLookupThreadByThreadId"):
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
    for rel in CUSTOM_OBJECT_EDITS:
        path=a.sdk/rel
        if path!=ob:replacements[path]=patch_guest_objects(rel,path.read_text())
    for path,updated in replacements.items():
        path.write_text(updated)
    tests.write_text(old+"\n"+a.tests.read_text())
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
if __name__=="__main__":main()
