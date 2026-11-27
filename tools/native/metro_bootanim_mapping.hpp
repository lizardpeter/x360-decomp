#pragma once
// Mapping/import/audio integrity gates shared with the independently
// validated isolated original-animation launch. No guest execution here.
#include <rex/kernel/title_runtime.h>
#include <rex/kernel/guest_memory.h>
#include <rex/kernel/module.h>
#include <rex/kernel/object/module_object.h>
#include <rex/kernel/object/object_table.h>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include "metro_bootanim_live_proofs.hpp"

namespace metro_intro {
inline constexpr rex::u32 kStart=0x98020E60u;
inline constexpr rex::u32 kControl=0x98020EC8u;
inline constexpr rex::u32 kControlFlagA=0x98077760u;
inline constexpr rex::u32 kControlFlagB=0x98077761u;
inline bool verify_mapping(rex::kernel::TitleRuntime& title,rex::kernel::X_HANDLE handle) {
    auto fail=[](const char* stage) {
        std::cout<<"METRO_INTRO fail "<<stage<<std::endl;return false;
    };
    auto& registry=title.GetModuleRegistry();
    auto object=title.GetObjectTable().Get<rex::kernel::ModuleObject>(handle);
    auto* xex=object?object->GetXEX():nullptr;
    if (!xex || xex->GetBaseAddress()!=0x98000000u || xex->GetImageSize()!=638976u ||
        xex->GetEntryPoint()!=0 || object->user.entry_point!=0 ||
        !object->hmodule_ptr || !xex->IsExecutable())return fail("original_identity");
    for (rex::u16 ordinal=1;ordinal<=3;++ordinal) {
        constexpr rex::u32 exports[]={0x98020E60,0x98020EC8,0x98020ED8};
        const auto target=xex->GetExportAddress(ordinal);
        if (target!=exports[ordinal-1] || !title.FindFunction(target))
        return fail("export_mapping");
    }
    std::cout<<"METRO_INTRO pass identity_and_exports"<<std::endl;
    auto kernel_handle=registry.FindKernelModule("xboxkrnl");
    if (!kernel_handle)return fail("kernel_module");
    auto kernel=title.GetObjectTable().Get<rex::kernel::ModuleObject>(*kernel_handle);
    if (!kernel)return fail("kernel_object");
    auto& mem=title.GetGuestMemory();
    unsigned functions=0,variables=0,failures=0;
    for (const auto& proof:kBootanimImports) {
        unsigned matches=0;
        for (const auto& lib:xex->GetImportLibraries()) {
        if (lib.name!="xboxkrnl")continue;
        for (const auto& item:lib.imports)
            if (item.ordinal==proof.ordinal && item.value_address==proof.slot &&
            item.thunk_address==proof.thunk)++matches;
        }
        const auto target=proof.thunk?proof.thunk:kernel->GetVariable(proof.ordinal);
        auto actual=mem.Load<rex::be_u32>(proof.slot);
        if (matches!=1 || !target || !actual ||
        (proof.thunk?!bool(title.FindFunction(target)):!bool(mem.Load<rex::be_u32>(target)))) {
        ++failures;
        std::cout<<"METRO_INTRO unresolved ordinal=0x"<<std::hex<<proof.ordinal
             <<" slot=0x"<<proof.slot<<" target=0x"<<target<<std::dec<<std::endl;
        continue;
        }
        if (static_cast<rex::u32>(*actual)!=target) {
        const rex::u32 old=*actual;
        // Only accept an unbound or exact original relocation marker.
        const bool marker=old==0 || (old&0xFF00FFFFu)==proof.ordinal ||
            (!proof.thunk && old==(0xD000BEEFu|(rex::u32(proof.ordinal)<<16)));
        if (!marker) {++failures;continue;}
        const bool writable=bool(mem.GetWritableSpan(proof.slot,4));
        if (!writable && !mem.Protect(proof.slot,4,rex::kernel::GuestProtect::kReadWrite)) {
            ++failures;continue;
        }
        const auto stored=mem.Store(proof.slot,rex::be_u32(target));
        const bool restored=writable || bool(mem.Protect(proof.slot,4,rex::kernel::GuestProtect::kReadOnly));
        actual=mem.Load<rex::be_u32>(proof.slot);
        if (!stored || !restored || !actual || static_cast<rex::u32>(*actual)!=target) {
            ++failures;continue;
        }
        }
        if (proof.thunk)++functions;else ++variables;
    }
    std::cout<<"METRO_INTRO imports functions="<<functions<<" variables="<<variables
         <<" failures="<<failures<<std::endl;
    if (failures || functions!=104 || variables!=10)return fail("import_integrity");
    rex::u32 address=0,size=0;
    if (object->GetSection("audio",&address,&size) || address!=kAudioAddress || size!=kAudioBytes)
        return fail("audio_lookup");
    const auto bytes=mem.GetReadOnlySpan(address,size);
    if (!bytes)return fail("audio_mapping");
    std::uint64_t hash=0xcbf29ce484222325ull;
    for (auto byte:*bytes) {hash^=std::to_integer<unsigned char>(byte);hash*=0x100000001b3ull;}
    if (hash!=kAudioDigest)return fail("audio_identity");
    std::cout<<"METRO_INTRO pass original_audio bytes="<<size<<std::endl;
    return true;
}
inline bool load(rex::kernel::TitleRuntime& title,rex::u32* hmodule) {
    auto& registry=title.GetModuleRegistry();
    if (registry.FindUserModule("bootanim.xex"))return false;
    const auto loaded=registry.LoadUserModule("game:\\bootanim.xex",false);
    if (!loaded || !*loaded || !verify_mapping(title,*loaded))return false;
    auto object=title.GetObjectTable().Get<rex::kernel::ModuleObject>(*loaded);
    if (!object || !object->hmodule_ptr)return false;
    *hmodule=object->hmodule_ptr;
    std::cout<<"METRO_INTRO pass loaded_as_user_module"<<std::endl;
    return true;
}
}
