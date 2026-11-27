#pragma once
// Verify actual original profile module load/unload in the original dashboard
// runtime, WITHOUT invoking their original DllMain or account functions.
#include <rex/kernel/title_runtime.h>
#include <rex/kernel/guest_memory.h>
#include <rex/kernel/module.h>
#include <rex/kernel/object/module_object.h>
#include <rex/kernel/object/object_table.h>
#include <rex/kernel/function_dispatcher.h>
#include <iostream>
#include <string>
#include <cstddef>
#include "metro_profile_proofs.hpp"

namespace metro_profile {
inline bool verify_imports(rex::kernel::TitleRuntime& title,
                           const rex::kernel::XEXModule& image,
                           const rex::kernel::XEXModule& xam,
                           const ModuleProof& proof) {
    unsigned libraries=0;
    for (const auto& lib:image.GetImportLibraries()) {
        if (lib.name=="xam") {
            if (lib.imports.size()!=proof.xam_count) return false;
            ++libraries;
        } else if (lib.name=="xboxkrnl") {
            if (lib.imports.size()!=proof.kernel_count) return false;
            ++libraries;
        } else return false;
    }
    if (libraries!=2) return false;
    auto verify=[&](const OriginalBinding* bindings,std::size_t count,bool retail) {
        for (std::size_t i=0;i<count;++i) {
            const auto& b=bindings[i];
            unsigned matches=0;
            for (const auto& lib:image.GetImportLibraries()) {
                if (lib.name!=(retail?"xam":"xboxkrnl")) continue;
                for (const auto& imp:lib.imports)
                    if (imp.ordinal==b.ordinal && imp.value_address==b.slot &&
                        imp.thunk_address==b.thunk) ++matches;
            }
            const auto slot=title.GetGuestMemory().Load<rex::be_u32>(b.slot);
            if (matches!=1 || !slot || static_cast<rex::u32>(*slot)!=b.thunk ||
                !title.FindFunction(b.thunk) ||
                (retail && (xam.GetExportAddress(b.ordinal)!=b.target ||
                            !title.FindFunction(b.target)))) {
                std::cout<<"METRO_PROFILE_PREFLIGHT fail "<<proof.name
                         <<" ordinal="<<std::hex<<b.ordinal<<std::dec<<std::endl;
                return false;
            }
        }
        return true;
    };
    return verify(proof.xam,proof.xam_count,true) &&
           verify(proof.kernel,proof.kernel_count,false);
}

inline bool verify_load_cycles(rex::kernel::TitleRuntime& title,
                               const rex::kernel::XEXModule& xam,
                               rex::kernel::X_HANDLE retail_handle,
                               rex::u32 dashboard_entry,rex::u32 hud_entry) {
    auto& registry=title.GetModuleRegistry();
    const auto original_dash=title.FindFunction(dashboard_entry);
    const auto original_hud=title.FindFunction(hud_entry);
    const auto original_xam=title.FindFunction(xam.GetEntryPoint());
    if (!original_dash || !original_hud || !original_xam || title.IsRunning()) return false;
    std::size_t bindings=0,cycles=0;
    for (unsigned round=0;round<2;++round) {
        for (const auto& proof:kModules) {
            const std::string alias="flash:\\"+std::string(proof.name);
            if (registry.FindUserModule(proof.name) || title.FindFunction(proof.entry))
                return false;
            // Alternate actual original guest spellings across the two rounds.
            const auto handle=registry.LoadUserModule(round?alias:std::string(proof.name),false);
            if (!handle || !*handle) {
                std::cout<<"METRO_PROFILE_PREFLIGHT fail "<<proof.name<<" load"<<std::endl;
                return false;
            }
            bool valid=false;
            {
                auto module=title.GetObjectTable().Get<rex::kernel::ModuleObject>(*handle);
                const auto* image=module?module->GetXEX():nullptr;
                valid=image && module->user.is_dll_module &&
                    image->GetBaseAddress()==proof.base && image->GetImageSize()==proof.size &&
                    image->GetEntryPoint()==proof.entry && module->user.entry_point==proof.entry &&
                    title.FindFunction(proof.entry) &&
                    registry.GetModule(alias,true).value_or(0)==*handle &&
                    title.FindGuestModule("xam.xex")==retail_handle &&
                    verify_imports(title,*image,xam,proof);
            } // Release the module object pin before unloading its guest image.
            registry.UnloadUserModule(*handle,false);
            if (!valid || registry.FindUserModule(proof.name) || title.FindFunction(proof.entry))
                return false;
            for (std::size_t i=0;i<proof.xam_count;++i)
                if (title.FindFunction(proof.xam[i].thunk)) return false;
            for (std::size_t i=0;i<proof.kernel_count;++i)
                if (title.FindFunction(proof.kernel[i].thunk)) return false;
            // Other live native modules and the selected XAM stay mapped.
            if (title.FindGuestModule("xam.xex")!=retail_handle ||
                title.FindFunction(dashboard_entry)!=original_dash ||
                title.FindFunction(hud_entry)!=original_hud ||
                title.FindFunction(xam.GetEntryPoint())!=original_xam || title.IsRunning())
                return false;
            ++cycles;
            bindings+=proof.xam_count;
            std::cout<<"METRO_PROFILE_PREFLIGHT pass "<<proof.name
                     <<" round="<<round+1<<" xam="<<proof.xam_count
                     <<" kernel="<<proof.kernel_count<<" guest_executed=false"<<std::endl;
        }
    }
    std::cout<<"METRO_PROFILE_PREFLIGHT total cycles="<<cycles<<" xam_bindings="<<bindings
             <<" guest_executed=false"<<std::endl;
    return cycles==10 && bindings==1420;
}
}
