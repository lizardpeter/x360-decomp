#!/usr/bin/env python3
"""Apply pinned Metro loader and kernel contract corrections."""
import argparse
import json
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION
from prepare_recompilation import ROOT

MERGE_OLD = """  for (const auto& library : image_->GetImports()) {
    SetupLibraryImports(library.name, library);
  }"""
MERGE_NEW = """  // Merge identical library identities before any import relocation.
  // Retail Metro splits one XAM library over two raw header records.
  if (base_address_ == 0x92000000 || base_address_ == 0x815F0000) {
    std::vector<filesystem::XEXImportLibrary> merged;
    for (const auto& library : image_->GetImports()) {
      auto found = std::ranges::find_if(merged, [&](const auto& entry) {
        return entry.name == library.name;
      });
      if (found == merged.end()) {
        merged.push_back(library);
      } else {
        if (found->id != library.id || found->version.value != library.version.value ||
            found->min_version.value != library.min_version.value) {
          REXSYS_FAIL(false, "Conflicting repeated XEX import library {}", library.name);
        }
        found->records.insert(found->records.end(), library.records.begin(), library.records.end());
      }
    }
    const u64 image_limit = u64{base_address_} + GetImageSize();
    std::unordered_map<u32, bool> addresses;
    for (const auto& library : merged) {
      std::unordered_map<u32, bool> records;
      for (const u32 address : library.records) {
        if (address < base_address_ || u64{address} + 4 > image_limit || (address & 3) ||
            !addresses.emplace(address, true).second) {
          REXSYS_FAIL(false, "Invalid or duplicate original import address {:08X}", address);
        }
        const u32 word = *GetAddressSpace()->TranslateVirtual<be_u32*>(address);
        const u32 kind = word >> 24;
        const u32 ordinal = word & 0xFFFF;
        if (kind > 1 || !records.emplace((kind << 16) | ordinal, true).second) {
          REXSYS_FAIL(false, "Conflicting import kind/ordinal {}:{:04X}", library.name, ordinal);
        }
      }
    }
    REXSYS_INFO("METRO_IMPORT_MERGE raw={} merged={}", image_->GetImports().size(), merged.size());
    for (const auto& library : merged) {
      if (!SetupLibraryImports(library.name, library)) return false;
    }
  } else {
    for (const auto& library : image_->GetImports()) {
      if (!SetupLibraryImports(library.name, library)) return false;
    }
  }"""
SYMBOL_OLD = """    for (const auto& import : lib.imports) {
      BinarySymbol sym;"""
SYMBOL_NEW = """    for (const auto& import : lib.imports) {
      // A value-only import has no executable symbol.
      if (!import.thunk_address) continue;
      BinarySymbol sym;"""
PTE_OLD = """  if (heap->GetPageSize() < 65536) {
    result |= 0x40000000;
  }
  return result & 0x400FFFFF;"""
PTE_NEW = """  if (heap->GetPageSize() < 65536) {
    result |= 0x40000000;
    // Retail 17559's Lua buffer check requires bit 0 for readable
    // committed pages of the dashboard image. Never grant it to free
    // or inaccessible pages.
    const u32 guest = address.GetGuestAddress();
    if (guest >= 0x92000000 && guest < 0x93028000) {
      kernel::HeapAllocation region{};
      if (heap->QueryRegionInfo(guest, &region) &&
          (region.state & kernel::kMemoryAllocationCommit) &&
          (region.protect & kernel::kMemoryProtectRead)) {
        result |= 1;
      }
    }
  }
  return result & 0x400FFFFF;"""
EVENT_OLD = """  module.SetVariable(0x02DB,
                     kernel_globals + offsetof(KernelGuestGlobals, UsbdBootEnumerationDoneEvent));

  return handle;"""
EVENT_NEW = """  module.SetVariable(0x02DB,
                     kernel_globals + offsetof(KernelGuestGlobals, UsbdBootEnumerationDoneEvent));

  // No physical storage error or USB driver request is pending at hosted
  // startup. Back the two imports with real unsignaled dispatcher objects.
  // The object table resolves the waitable event lazily from this header.
  for (const u16 ordinal : {u16{0x02DC}, u16{0x02F1}}) {
    const u32 address = mem->SystemHeapAlloc(sizeof(X_DISPATCH_HEADER));
    if (!address) {
      REXSYS_ERROR("Failed to allocate hosted kernel event {:04X}", ordinal);
      return 0;
    }
    auto* header = mem->TranslateVirtual<X_DISPATCH_HEADER*>(address);
    std::memset(header, 0, sizeof(*header));
    header->type = 0;
    header->size = sizeof(X_DISPATCH_HEADER) / sizeof(u32);
    header->signal_state = 0;
    header->wait_list_flink = address + offsetof(X_DISPATCH_HEADER, wait_list_flink);
    header->wait_list_blink = header->wait_list_flink;
    module.SetVariable(ordinal, address);
  }

  return handle;"""
PAD_OLD = """      result = state.ReadUserLocked(user);
    }
  }
  state.Fire(events);
  return result;
}

Result<rex::hid::PadCapabilities>"""
PAD_NEW = """      result = state.ReadUserLocked(user);
    }
  }
  state.Fire(events);
  if (result && user == 0) {
    static std::atomic<u16> previous{0};
    const u16 buttons = result->state.buttons;
    if (previous.exchange(buttons, std::memory_order_relaxed) != buttons) {
      REXHID_INFO("METRO_PAD user=0 buttons=0x{:04X}", buttons);
    }
  }
  return result;
}

Result<rex::hid::PadCapabilities>"""
TRACE_ANCHOR = "#define REX_STUB(subroutine)"
TRACE_HELPER = r'''// Bounded, observational Metro stub trace. No register changes.
#define REX_METRO_TRACE_STUB(subroutine)                                           \
  do {                                                                            \
    const ::rex::u32 metro_lr = static_cast<::rex::u32>(ctx.lr);                     \
    if ((metro_lr >= 0x815F0000u && metro_lr < 0x81C00000u) ||                       \
        (metro_lr >= 0x92000000u && metro_lr < 0x93028000u)) {                        \
      static ::std::atomic_uint metro_count{0};                                     \
      if (metro_count.fetch_add(1, ::std::memory_order_relaxed) < 4)                 \
        REXCPU_WARN("METRO_STUB name={} lr=0x{:08X} r3=0x{:08X} r4=0x{:08X} r5=0x{:08X} r6=0x{:08X}", \
                    #subroutine, metro_lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32); \
    }                                                                             \
  } while (0)
'''

def replace(source, old, new):
    if source.count(old)!=1 or new in source:
        raise ValueError("unexpected SDK patch anchor")
    return source.replace(old,new,1)

def trace(source):
    if source.count(TRACE_ANCHOR)!=1 or "REX_METRO_TRACE_STUB" in source:
        raise ValueError("unexpected stub macro")
    source=source.replace(TRACE_ANCHOR,TRACE_HELPER+"\n"+TRACE_ANCHOR,1)
    lines=source.splitlines(keepends=True)
    hits=0
    for i in range(len(lines)-1,-1,-1):
        if lines[i].startswith("    static constinit ::std::atomic_flag rex_stub_seen_;"):
            hits+=1
            lines.insert(i+1,"    REX_METRO_TRACE_STUB(subroutine); "+chr(92)+"\n")
    if hits!=3:raise ValueError("unexpected SDK stub forms")
    return "".join(lines)

def verify_records():
    metadata=json.loads((ROOT/"analysis/dash_17559/xex.json").read_text())
    libraries=metadata["imports"]
    if len(libraries)!=3 or [x["slot_count"] for x in libraries]!=[623,421,584]:
        raise ValueError("unexpected original record inventory")
    if any(libraries[0][k]!=libraries[1][k] for k in
           ("library","library_id","version","minimum_version")):
        raise ValueError("repeated library identities differ")
    addresses=[a for r in libraries for a in r["slot_addresses"]]
    if len(set(addresses))!=1628 or len(addresses)!=1628:
        raise ValueError("original record addresses are not unique")

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    verify_records()
    changes={
        "src/kernel/xex_module.cpp":lambda s:replace(replace(s,MERGE_OLD,MERGE_NEW),SYMBOL_OLD,SYMBOL_NEW),
        "src/kernel/xboxkrnl/xboxkrnl_memory.cpp":lambda s:replace(s,PTE_OLD,PTE_NEW),
        "src/kernel/xboxkrnl/xboxkrnl_module.cpp":lambda s:replace(s,EVENT_OLD,EVENT_NEW),
        "include/rex/ppc/hook.h":trace,
        "src/hid/input_system.cpp":lambda s:replace(s,PAD_OLD,PAD_NEW),
    }
    updated={a.sdk/path:fn((a.sdk/path).read_text()) for path,fn in changes.items()}
    for path,content in updated.items():path.write_text(content)
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
    print("Metro loader pairing, mapped-page contract, event variables and stub/pad observations")
if __name__=="__main__":main()
