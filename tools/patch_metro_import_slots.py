#!/usr/bin/env python3
"""Patch five verified Metro function imports and one XAM data import during XEX loading.

The five code imports are forwarded to the native XAM exports. The data
import is bound directly to the original writable XAM image address.
"""
import argparse
import subprocess
from pathlib import Path
import json
import re
from prepare_recompilation import ROOT, EXPECTED
from patch_rexglue_imports import REVISION
from stage_metro_xam_aot import BINDINGS, rows, verify_bindings

VALUE_SLOTS = {
    0x0546: 0x92000BC4,
    0x0547: 0x92000BCC,
    0x0548: 0x92000BC8,
    0x0549: 0x92000BD0,
    0x054B: 0x920005D0,
}
VARIABLE_ORDINAL = 0x03DB
VARIABLE_SLOT = 0x92000550
VARIABLE_THUNK_SLOT = 0x9293D11C
VARIABLE_TARGET = 0x81A87F20
VARIABLE_OLD = '''          } else {
            *record_slot = 0xD000BEEF | (kernel_export->ordinal & 0xFFF) << 16;
            REXSYS_WARN("Variable import {}:{:#x} ({}) not implemented", base_name, ordinal,
                        kernel_export->name);
          }'''
VARIABLE_NEW = '''          } else if (base_address_ == 0x92000000 && base_name == "xam" &&
                     ordinal == 0x03DB && record_addr == 0x92000550 &&
                     kernel_export->name == "g_XuiAutomation") {
            *record_slot = 0x81A87F20;
            REXSYS_DEBUG("Patched verified Metro XAM variable import {}:{:#x} ({}) -> {:#x}",
                         base_name, ordinal, kernel_export->name, 0x81A87F20);
          } else {
            *record_slot = 0xD000BEEF | (kernel_export->ordinal & 0xFFF) << 16;
            REXSYS_WARN("Variable import {}:{:#x} ({}) not implemented", base_name,
                        ordinal, kernel_export->name);
          }'''

OLD = '''      REXSYS_DEBUG("Patched function import {}:{:#x} ({}) -> {:#x}", base_name, ordinal,
                   kernel_export->name, import_info.thunk_address);
    }'''
CONDITIONS = " ||\n         ".join(
    f"(ordinal == 0x{o:04X} && import_info.value_address == 0x{v:08X} && "
    f"import_info.thunk_address == 0x{BINDINGS[o][0]:08X})"
    for o, v in sorted(VALUE_SLOTS.items()))
NEW = OLD + ''' else if (!kernel_export && base_address_ == 0x92000000 &&
               base_name == "xam" &&
        (''' + CONDITIONS + ''')) {
      *GetAddressSpace()->TranslateVirtual<be_u32*>(import_info.value_address) =
          import_info.thunk_address;
      REXSYS_DEBUG("Patched verified Metro XAM function import {:#x} -> {:#x}",
                   ordinal, import_info.thunk_address);
    }'''

def verify_slots(imports, exports):
    verify_bindings(imports, exports)
    for ordinal, slot in VALUE_SLOTS.items():
        matches = [r for r in imports if r["library"] == "xam.xex" and
                   int(r["ordinal"], 16) == ordinal]
        if len(matches) != 1 or matches[0]["value_slots"] != f"{slot:08X}":
            raise ValueError(f"unexpected Metro value slot {ordinal:04X}")

    # This is a data import, not a thunk. Verify both ends against the
    # hash-verified retail images and require a writable, non-executable XAM
    # section before hard-wiring the guest address.
    imports_3db = [r for r in imports if r["library"] == "xam.xex" and
                   int(r["ordinal"], 16) == VARIABLE_ORDINAL]
    exports_3db = [r for r in exports if int(r["ordinal"], 16) == VARIABLE_ORDINAL]
    if (len(imports_3db) != 1 or imports_3db[0]["value_slots"] != f"{VARIABLE_SLOT:08X}" or
            imports_3db[0]["thunk_slots"] != f"{VARIABLE_THUNK_SLOT:08X}" or len(exports_3db) != 1 or
            int(exports_3db[0]["address"], 16) != VARIABLE_TARGET):
        raise ValueError("unexpected Metro g_XuiAutomation import/export binding")
    meta = json.loads((ROOT/"analysis/xam_17559/decoded.json").read_text())
    if meta.get("state") != "verified" or meta.get("source_sha256") != EXPECTED["xam_17559"]:
        raise ValueError("unverified retail XAM image for data import")
    in_writable_data = any(
        (section["flags"] & 0x80000000) and not (section["flags"] & 0x20000000) and
        meta["image_base"] + section["rva"] <= VARIABLE_TARGET and
        VARIABLE_TARGET + 4 <= meta["image_base"] + section["rva"] + section["loaded_bytes"]
        for section in meta["pe"]["sections"]
    )
    if VARIABLE_TARGET & 3 or not in_writable_data:
        raise ValueError("g_XuiAutomation is not in a verified writable XAM data section")


def verify_variable_catalog(source):
    if not re.search(
            r"REX_EXPORT\(xam,\s*0x000003DB,\s*g_XuiAutomation,\s*kVariable\)",
            source):
        raise ValueError("SDK XAM catalog does not identify 03DB as g_XuiAutomation variable")

def corrected(source):
    if (NEW in source or source.count(OLD) != 1 or VARIABLE_NEW in source or
            source.count(VARIABLE_OLD) != 1):
        raise ValueError("unexpected or previously patched XEX loader")
    return source.replace(VARIABLE_OLD, VARIABLE_NEW, 1).replace(OLD, NEW, 1)

# 17559 huduiskin is a non-executable resource image, not a PE.
SKIN_HEADER_ANCHOR = "}  // namespace rex::filesystem\n"
SKIN_HELPER = r"""
// Exact original 17559 HUD skin layout. Normal compressed-block verification
// still applies; no entry point, imports, exports or code pages are accepted.
inline bool IsMetroHudSkinResource(const IXEXImage& xex, std::span<const u8> bytes) {
  using namespace rex::kernel;
  constexpr u32 base = 0x90F90000, size = 233472;
  const auto& sec = xex.GetSecurity();
  const auto header = xex.GetHeaderBytes();
  if (xex.IsPatch() || sec.load_address != base || sec.image_size != size ||
      xex.GetImageSize() != size || bytes.size() != size || header.size() != 4096 ||
      sec.export_table || !xex.GetImports().empty() ||
      xex.GetOptHeaderValue(kXEXHeaderEntryPoint).value_or(0) ||
      xex.GetOptHeaderValue(kXEXHeaderImageBaseAddress).value_or(base) != base ||
      xex.GetOptHeader<XEXOptDataDirectory>(kXEXHeaderExportsByName))
    return false;
  // The original image audit recovered four read-only 4 KiB page runs.
  constexpr u32 page_counts[] = {16,16,16,9};
  if (sec.pages.size()!=4 || !(sec.image_flags & kXEXImagePageSize4KB)) return false;
  for (size_t i=0;i<4;++i)
    if (sec.pages[i].type != kXEXSectionReadOnlyData ||
        sec.pages[i].page_count != page_counts[i]) return false;
  const auto* format = xex.GetOptHeader<XEXOptFileFormatInfo>(kXEXHeaderFileFormatInfo);
  const auto* info = xex.GetOptHeader<XEXOptResourceInfo>(kXEXHeaderResourceInfo);
  if (!format || reinterpret_cast<const u8*>(format) != header.data()+704 ||
      static_cast<u16>(format->encryption_type) != kXEXEncryptionNone ||
      static_cast<u16>(format->compression_type) != kXEXCompressionNormal ||
      !info || reinterpret_cast<const u8*>(info) != header.data()+668 ||
      static_cast<u32>(info->size) != 36)
    return false;
  constexpr u8 expected[] = {
    's','k','i','n',0,0,0,0, 0x90,0xF9,0x00,0x00, 0x00,0x01,0x28,0x4B,
    'x','a','m',0,0,0,0,0, 0x90,0xFA,0x28,0x80, 0x00,0x02,0x61,0xA5
  };
  for (size_t i=0;i<sizeof(expected);++i)
    if (header[672+i]!=expected[i]) return false;
  for (const size_t off : {size_t{0},size_t{0x12880}})
    if (bytes[off]!='X' || bytes[off+1]!='U' || bytes[off+2]!='I' || bytes[off+3]!='Z')
      return false;
  return true;
}

"""
SKIN_DECODE_OLD = "    if (decoded && IsExecutable(image)) {"
SKIN_DECODE_NEW = "    if (decoded && (IsExecutable(image) || IsMetroHudSkinResource(*this, image))) {"
SKIN_LOAD_START = "  auto parsed_pe = GetKernelServices()->file_system->ParsePE("
SKIN_LOAD_END = "  std::vector<u8>().swap(pending_image_);\n  for (auto& section : pe_->sections)"
def corrected_skin(header, decoder, loader):
    if "IsMetroHudSkinResource" in header or header.count(SKIN_HEADER_ANCHOR)!=2:
        raise ValueError("unexpected SDK XEX interface")
    pos=header.rindex(SKIN_HEADER_ANCHOR)
    header=header[:pos]+SKIN_HELPER+header[pos:]
    if decoder.count(SKIN_DECODE_OLD)!=1 or SKIN_DECODE_NEW in decoder:
        raise ValueError("unexpected SDK XEX decoder")
    decoder=decoder.replace(SKIN_DECODE_OLD,SKIN_DECODE_NEW,1)
    if loader.count(SKIN_LOAD_START)!=1 or loader.count(SKIN_LOAD_END)!=1 or "IsMetroHudSkinResource" in loader:
        raise ValueError("unexpected SDK XEX PE load")
    begin=loader.index(SKIN_LOAD_START)
    end=loader.index(SKIN_LOAD_END,begin)
    original=loader[begin:end]
    replacement="""  if (filesystem::IsMetroHudSkinResource(*image_,
          std::span<const u8>(pending_image_.data(), image_end))) {
    *pe_ = {};
    std::memcpy(GetAddressSpace()->TranslateVirtual(base_address_),
                pending_image_.data(), image_end);
    REXSYS_INFO("METRO_HUD_SKIN resource-only image mapped at {:08X} bytes={}",
                base_address_, image_end);
  } else {
"""+ "".join("  "+line+"\n" for line in original.splitlines())+"  }\n"
    loader=loader[:begin]+replacement+loader[end:]
    return header,decoder,loader

def verify_skin_inventory():
    meta=json.loads((ROOT/"analysis/huduiskin_17559/decoded.json").read_text())
    if (meta.get("state")!="verified" or meta.get("pe") is not None or
        meta.get("source_sha256")!="fdbe68d20fa6b013282ce8f21cebddc34fe4e3a92a71c28983d63f288d2252cc" or
        meta.get("sha256")!="d7cc1f96a9ac09853d325c9522ba257e5e23c43c819de5007f36fb49e33cedf4" or
        meta.get("image_base")!=0x90F90000 or meta.get("image_bytes")!=233472 or
        meta.get("distinct_imports")!=0 or meta.get("resource_count")!=2):
        raise ValueError("original HUD skin inventory mismatch")
    records=json.loads((ROOT/"analysis/huduiskin_17559/resource_hashes.json").read_text())
    if [(r["id"],r["address"],r["bytes"],r["magic"]) for r in records]!=[
            ("skin","90F90000",75851,"5855495a"),("xam","90FA2880",156069,"5855495a")]:
        raise ValueError("original HUD skin resource layout mismatch")

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk", type=Path)
    a = p.parse_args()
    revision = subprocess.check_output(["git", "-C", str(a.sdk), "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        raise ValueError("unexpected SDK revision")
    verify_slots(rows(ROOT/"analysis/dash_17559/imports.tsv"),
                 rows(ROOT/"analysis/xam_17559/exports.tsv"))
    verify_variable_catalog((a.sdk/"src/kernel/xam/export_table.inc").read_text())
    path = a.sdk/"src/kernel/xex_module.cpp"
    verify_skin_inventory()
    header = a.sdk/"include/rex/filesystem/xex.h"
    decoder = a.sdk/"src/filesystem/xex.cpp"
    h,d,l = corrected_skin(header.read_text(),decoder.read_text(),corrected(path.read_text()))
    header.write_text(h)
    decoder.write_text(d)
    path.write_text(l)
    subprocess.run(["git", "-C", str(a.sdk), "diff", "--check"], check=True)

if __name__ == "__main__":
    main()
