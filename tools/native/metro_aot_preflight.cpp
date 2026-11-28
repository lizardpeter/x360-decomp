// Host-only mapping and dispatch preflight for the original Metro/XAM pair.
// This never launches the dashboard or executes XAM's entry point.
// It does execute one verified stackless heap-configuration leaf.
#include <rex/app/app.h>
#include <rex/apu/audio_system.h>
#include <rex/gpu/graphics_system.h>
#include <rex/hid/input_system.h>
#include <rex/ui/ui_system.h>
#include <rex/kernel/title_runtime.h>
#include <rex/kernel/title_paths.h>
#include <rex/kernel/module.h>
#include <rex/kernel/object/module_object.h>
#include <rex/kernel/object/object_table.h>
#include <rex/setting.h>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cstddef>
#include <string_view>
#include <array>
#include <algorithm>
#include <rex/kernel/guest_memory.h>
#include "generated/dash_17559_init.h"
#include "metro_preflight_bindings.hpp"
#include "metro_resource_proofs.hpp"
#include "metro_aot_boot.hpp"
#include "metro_profile_mapping.hpp"

namespace {
using rex::kernel::ModuleObject;
using rex::kernel::TitleRuntime;

bool fail(const char* stage) {
    std::cout << "METRO_PREFLIGHT fail " << stage << std::endl;
    return false;
}

template <std::size_t N>
bool verify_resources(TitleRuntime& title, ModuleObject& module, const char* label,
                      const MetroResourceProof (&proofs)[N]) {
    for (const auto& proof : proofs) {
        rex::u32 address=0, size=0;
        const auto status=module.GetSection(proof.name,&address,&size);
        if (status || address!=proof.address || size!=proof.size) {
            std::cout<<"METRO_RESOURCE fail "<<label<<" "<<proof.name<<" lookup"<<std::endl;
            return false;
        }
        auto bytes=title.GetGuestMemory().GetReadOnlySpan(address,size);
        if (!bytes) {
            std::cout<<"METRO_RESOURCE fail "<<label<<" "<<proof.name<<" mapping"<<std::endl;
            return false;
        }
        std::uint64_t digest=0xcbf29ce484222325ull;
        for (auto byte : *bytes) {
            digest^=std::to_integer<unsigned char>(byte);
            digest*=0x100000001b3ull;
        }
        if (digest!=proof.digest) {
            std::cout<<"METRO_RESOURCE fail "<<label<<" "<<proof.name<<" content"<<std::endl;
            return false;
        }
        std::cout<<"METRO_RESOURCE pass "<<label<<" "<<proof.name<<" bytes="<<size<<std::endl;
    }
    return true;
}

// These are the original wide-string length and copy callees, not hosted
// substitutes. Both XUI string-copy wrappers call length with r3=source,
// then call copy with r3=allocated destination, r4=length+1, r5=source.
// See original cross-module evidence 46068603654. The diagnostic is opt-in
// and isolated from live startup, guest account data and original resources.
bool verify_header_strings(TitleRuntime& title) {
    auto& mem=title.GetGuestMemory();
    auto allocation=mem.Allocate(65536,4096,rex::kernel::GuestProtect::kReadWrite);
    if(!allocation)return false;
    const rex::u32 base=*allocation;
    auto run=[&]() {
        constexpr std::array<std::u16string_view,12> inputs{
            u"",u"v",u"ho",u"hom",u"home",u"social",u"games",u"movies & tv",
            u"apps",u"settings",u"\u00e9\u3042",u"0123456789abcdef"
        };
        struct Pair {const char* module;rex::u32 length,copy;};
        constexpr Pair pairs[]={{"dash",0x921996F8u,0x92198D90u},
                                {"xam",0x8172DAF0u,0x8172F2A8u}};
        unsigned failures=0,total=0;
        for(const auto& pair:pairs) {
            auto length=title.FindFunction(pair.length);
            auto copy=title.FindFunction(pair.copy);
            if(!length || !copy) {
                std::cout<<"METRO_HEADER_SELFTEST module="<<pair.module
                         <<" mapping=missing"<<std::endl;
                ++failures;continue;
            }
            for(unsigned i=0;i<inputs.size();++i) {
                const auto str=inputs[i];
                for(unsigned align=0;align<16;align+=2) {
                    const rex::u32 src=base+512+align,dst=base+4096+(14-align);
                    auto source=mem.GetWritableSpan(base+480,128);
                    auto dest=mem.GetWritableSpan(base+4064,128);
                    if(!source || !dest)return false;
                    std::fill(source->begin(),source->end(),std::byte{0x5a});
                    std::fill(dest->begin(),dest->end(),std::byte{0xa5});
                    for(unsigned j=0;j<str.size();++j)
                        if(!mem.Store(src+j*2,rex::be_u16{static_cast<rex::u16>(str[j])}))
                            return false;
                    if(!mem.Store(src+static_cast<rex::u32>(str.size()*2),rex::be_u16{0}))
                        return false;
                    std::array<std::byte,128> before{};
                    std::copy(source->begin(),source->end(),before.begin());
                    PPCContext count{};
                    count.r1.u64=base+0xf000;
                    count.r3.u64=src;
                    (*length)(count,title.GetMembase().GetBase());
                    const bool length_ok=count.r3.u32==str.size();
                    for(unsigned spare:{0u,3u}) {
                        std::fill(dest->begin(),dest->end(),std::byte{0xa5});
                        const auto capacity=static_cast<rex::u32>(str.size()+1+spare);
                        PPCContext cp{};
                        cp.r1.u64=base+0xf000;cp.r3.u64=dst;
                        cp.r4.u64=capacity;cp.r5.u64=src;
                        (*copy)(cp,title.GetMembase().GetBase());
                        bool data_ok=true;
                        for(unsigned j=0;j<=str.size();++j) {
                            auto actual=mem.Load<rex::be_u16>(dst+j*2);
                            const auto expected=j==str.size()?0u:static_cast<unsigned>(str[j]);
                            if(!actual || static_cast<rex::u16>(*actual)!=expected)data_ok=false;
                        }
                        const bool unchanged=std::equal(before.begin(),before.end(),source->begin());
                        const auto first=dst-(base+4064),end=first+capacity*2;
                        const bool guards=std::all_of(dest->begin(),dest->begin()+first,
                              [](std::byte x){return x==std::byte{0xa5};}) &&
                              std::all_of(dest->begin()+end,dest->end(),
                              [](std::byte x){return x==std::byte{0xa5};});
                        ++total;
                        if(!length_ok || !data_ok || !unchanged || !guards) {
                            ++failures;
                            std::cout<<"METRO_HEADER_SELFTEST fail module="<<pair.module
                                     <<" case="<<i<<" units="<<str.size()<<" alignment="<<align
                                     <<" capacity="<<capacity<<" actual_length="<<count.r3.u32
                                     <<" copy="<<data_ok<<" source="<<unchanged<<" guards="<<guards
                                     <<std::endl;
                        }
                    }
                }
            }
        }
        std::cout<<"METRO_HEADER_SELFTEST total="<<total<<" failures="<<failures<<std::endl;
        return total==384 && failures==0;
    };
    const bool passed=run();
    return bool(mem.Free(base)) && passed;
}

class MetroPreflight final : public rex::app::App {
public:
    MetroPreflight() : App("metro_preflight"), title_(kPPCImageConfig) {}
    ~MetroPreflight() override { title_.Unload(); }

    bool Check() {
        // Refuse accidental launch against a different entry or writable image tree.
        auto& paths = title_.GetTitlePaths();
        if (paths.game_root.Get().empty() || paths.entry.Get() != "dash.xex" ||
            paths.game_writable.Get())
            return fail("input_settings");

        if (!title_.Load())
            return fail("dashboard_load");
        if (!title_.IsLoaded() || title_.IsRunning())
            return fail("dashboard_state");
        std::cout << "METRO_PREFLIGHT pass dashboard_load" << std::endl;
        if (!metro_boot::mount_flash(title_)) return fail("flash_mount");
        std::cout << "METRO_PREFLIGHT pass flash_mount" << std::endl;

        auto& registry = title_.GetModuleRegistry();
        const auto exe = registry.GetExecutable();
        if (!exe)
            return fail("dashboard_handle");
        auto dash = title_.GetObjectTable().Get<ModuleObject>(*exe);
        const auto* dash_xex = dash ? dash->GetXEX() : nullptr;
        if (!dash_xex)
            return fail("dashboard_xex_missing");

        std::size_t mapping_count = 0;
        std::size_t zero_address_mappings = 0;
        bool entry_mapping = false;
        bool first_mapping_has_host = false;
        const PPCFuncMapping* first_mapping = kPPCImageConfig.func_mappings;
        if (first_mapping) first_mapping_has_host = first_mapping->host != nullptr;
        for (const PPCFuncMapping* mapping = first_mapping; mapping; ++mapping) {
            if (!mapping->address && !mapping->host) break;
            ++mapping_count;
            if (!mapping->address) ++zero_address_mappings;
            if (static_cast<rex::u32>(mapping->address) == kDashEntry && mapping->host)
                entry_mapping = true;
        }
        const auto entry_function = title_.FindFunction(kDashEntry);
        const bool entry_in_code_range =
            kDashEntry >= kPPCImageConfig.code_base &&
            static_cast<std::uint64_t>(kDashEntry) <
                static_cast<std::uint64_t>(kPPCImageConfig.code_base) +
                    kPPCImageConfig.code_size;
        std::cout << "METRO_PREFLIGHT identity base=0x" << std::hex
                  << dash_xex->GetBaseAddress() << " expected_base=0x" << kDashBase
                  << " size=0x" << dash_xex->GetImageSize() << " expected_size=0x" << kDashSize
                  << " entry=0x" << dash_xex->GetEntryPoint() << " expected_entry=0x" << kDashEntry
                  << " module_entry=0x" << dash->user.entry_point
                  << " code_base=0x" << kPPCImageConfig.code_base
                  << " code_size=0x" << kPPCImageConfig.code_size
                  << " image_base=0x" << kPPCImageConfig.image_base
                  << " image_size=0x" << kPPCImageConfig.image_size
                  << std::dec << " mappings=" << mapping_count
                  << " zero_address_mappings=" << zero_address_mappings
                  << " first_mapping_host=" << first_mapping_has_host
                  << " entry_mapping=" << entry_mapping
                  << " entry_in_code_range=" << entry_in_code_range
                  << " entry_registered=" << static_cast<bool>(entry_function)
                  << std::endl;
        if (dash_xex->GetBaseAddress() != kDashBase)
            return fail("dashboard_base");
        if (dash_xex->GetImageSize() != kDashSize)
            return fail("dashboard_size");
        if (dash_xex->GetEntryPoint() != kDashEntry ||
            dash->user.entry_point != kDashEntry)
            return fail("dashboard_entry");
        if (!entry_function)
            return fail("dashboard_entry_function");
        std::cout << "METRO_PREFLIGHT pass dashboard_identity" << std::endl;

        // The SDK's built-in hosted XAM is not the retail XAM user module.
        // Map the separately generated native library through the existing loader.
        // false explicitly prevents DLL_PROCESS_ATTACH / guest execution.
        if (metro_boot::find_retail_xam(registry))
            return fail("unexpected_preloaded_xam");
        const auto loaded = registry.LoadUserModule(metro_boot::kXamPath, false);
        if (!loaded || !*loaded)
            return fail("xam_load");
        const auto user = metro_boot::find_retail_xam(registry);
        const auto by_name = registry.FindUserModule("xam.xex");
        if (!user || *user != *loaded || !by_name || *by_name != *loaded)
            return fail("xam_registry");
        std::cout << "METRO_PREFLIGHT pass xam_registry" << std::endl;
        const auto kernel = registry.FindKernelModule("xam");
        if (!kernel || *kernel == *user)
            return fail("xam_isolation");

        auto module = title_.GetObjectTable().Get<ModuleObject>(*user);
        const auto* xam = module ? module->GetXEX() : nullptr;
        if (!xam || xam->GetBaseAddress() != kXamBase ||
            xam->GetImageSize() != kXamSize ||
            xam->GetEntryPoint() != kXamEntry ||
            !title_.FindFunction(kXamEntry))
            return fail("xam_identity");
        std::cout << "METRO_PREFLIGHT pass xam_load" << std::endl;
        if (!metro_boot::prepare_hosted_heap_flag(title_)) return fail("hosted_heap_flag");
        std::cout << "METRO_PREFLIGHT pass hosted_heap_flag" << std::endl;
        // Data-referenced leaf entries are not guaranteed by PDATA or exports.
        // Fail before original XAM initialization if any actual callback is
        // absent from the native dispatch table.
        constexpr rex::u32 callback_types[][8] = {
            {0x81A821E0,0x81A72B54,0x81A72734,0,0x816A7EE0,0,0xC,0x66746F4E},
            {0x81A82574,0x816E6CE0,0x816E6B10,0,0x816BB030,0,0x81A85484,7},
            {0x81A85494,0x816E6CE0,0x816E6B10,0x816F1200,0,0,0x81A85484,6},
            {0x81A93738,0x81897C50,0x8188B380,0x8188B388,0,0,0x81A85484,0x5370744D},
        };
        for (const auto& descriptor : callback_types) {
            for (rex::u32 index=0; index<7; ++index) {
                auto live=title_.GetGuestMemory().Load<rex::be_u32>(descriptor[0]+index*4);
                if (!live || static_cast<rex::u32>(*live)!=descriptor[index+1])
                    return fail("custom_object_descriptor");
                if (index<5 && descriptor[index+1] && !title_.FindFunction(descriptor[index+1]))
                    return fail("custom_object_callback_mapping");
            }
        }
        std::cout << "METRO_PREFLIGHT pass custom_object_callbacks" << std::endl;

        if (!metro_boot::verify_kernel_variables(title_,*dash_xex,kDashKernelVariables,"dash") ||
            !metro_boot::verify_kernel_variables(title_,*xam,kXamKernelVariables,"xam")) return fail("kernel_variables");
        std::cout << "METRO_PREFLIGHT pass kernel_variables" << std::endl;
        if (!metro_boot::verify_retail_routes(title_, *dash_xex, *xam))
            return fail("retail_export_mapping");
        std::cout << "METRO_PREFLIGHT pass all_retail_export_mappings" << std::endl;
        if (!metro_boot::verify_live_binding(title_, *dash_xex, *xam, kXamDataBinding, true))
            return fail("dashboard_data_import");
        std::cout << "METRO_PREFLIGHT pass xam_data_mapping" << std::endl;
        if (title_.FindGuestModule("xam.xex") != *kernel ||
            title_.SelectRetailXam(*kernel) || !title_.SelectRetailXam(*user) ||
            title_.SelectRetailXam(*user)) return fail("dynamic_xam_selection");
        for (auto alias : {"xam", "XAM.XEX", "game:\\xam.xex", "flash:\\xam.xex",
                           "\\Device\\Flash\\xam.xex", "\\SystemRoot\\xam.xex"})
            if (title_.FindGuestModule(alias) != *user) return fail("dynamic_xam_identity");
        if (registry.FindKernelModule("xam") != kernel ||
            title_.FindGuestModule("xboxkrnl.exe") != registry.GetModule("xboxkrnl.exe").value_or(0) ||
            title_.FindGuestModule("unloaded-test-module.xex"))
            return fail("dynamic_xam_isolation");
        std::cout << "METRO_PREFLIGHT pass dynamic_xam_identity" << std::endl;
        // Load the actual native HUD via the same guest alias as the live
        // dashboard, without invoking its original entry in this preflight.
        const auto hud_handle=registry.LoadUserModule("hud.xex",false);
        if (!hud_handle) return fail("hud_load");
        auto hud=title_.GetObjectTable().Get<ModuleObject>(*hud_handle);
        auto* hx=hud?hud->GetXEX():nullptr;
        if (!hx || hx->GetBaseAddress()!=0x913E0000 || hx->GetImageSize()!=299008 ||
            hx->GetEntryPoint()!=0x913F8D00 || !title_.FindFunction(0x913F8D00))
            return fail("hud_identity");
        std::size_t count=0;
        for (const auto& lib:hx->GetImportLibraries()) {
            if (lib.name!="xam") continue;
            for (const auto& import:lib.imports) {
                const auto value=title_.GetGuestMemory().Load<rex::be_u32>(import.value_address);
                const auto target=xam->GetExportAddress(static_cast<rex::u16>(import.ordinal));
                if (!value || static_cast<rex::u32>(*value)!=import.thunk_address ||
                    !target || !title_.FindFunction(target) || !title_.FindFunction(import.thunk_address))
                    return fail("hud_binding");
                ++count;
            }
        }
        if (count!=233) return fail("hud_binding_count");
        std::cout<<"METRO_PREFLIGHT pass hud_retail_mapping"<<std::endl;
        if (!verify_resources(title_,*dash,"dash",kDashResources) ||
            !verify_resources(title_,*module,"xam",kXamResources) ||
            !verify_resources(title_,*hud,"hud",kHudResources)) return fail("original_resource_integrity");
        std::cout<<"METRO_PREFLIGHT pass original_resource_integrity"<<std::endl;
        rex::u32 intro_hmodule=0;
        if (!metro_intro::load(title_,&intro_hmodule))return fail("bootanim_native_mapping");
        if (!intro_hmodule || !title_.FindFunction(metro_intro::kStart) ||
            !title_.FindFunction(metro_intro::kControl))return fail("bootanim_native_mapping");
        std::cout<<"METRO_PREFLIGHT pass bootanim_native_mapping"<<std::endl;
        const char* profile_check=std::getenv("X360_METRO_PROFILE_MODULE_PREFLIGHT");
        if (profile_check && std::string_view(profile_check)=="1") {
            if (!metro_profile::verify_load_cycles(title_,*xam,*user,kDashEntry,0x913F8D00))
                return fail("profile_module_mapping");
            std::cout<<"METRO_PREFLIGHT pass profile_module_mapping"<<std::endl;
        }
        const char* text_check=std::getenv("X360_METRO_TEXT_PREFLIGHT");
        if(text_check && std::string_view(text_check)=="1") {
            if(!verify_header_strings(title_))return fail("original_header_string_contract");
            std::cout<<"METRO_PREFLIGHT pass original_header_string_contract"<<std::endl;
        }
        if (title_.IsRunning())
            return fail("unexpected_guest_launch");

        return true;
    }

    void Release() { title_.Unload(); }

protected:
    rex::Result<void> OnConfigure(rex::SettingsRegistry&) override {
        // No window, GPU, audio or input backend needed for an image mapping gate.
        REX_TRY_VOID(GetUI().GetSettings().driver.SetText(rex::SettingLayer::kTitle, "none"));
        REX_TRY_VOID(GetInput().GetSettings().drivers.SetText(rex::SettingLayer::kTitle, "none"));
        REX_TRY_VOID(GetAudio().GetSettings().driver.SetText(rex::SettingLayer::kTitle, "none"));
        REX_TRY_VOID(GetGraphics().GetSettings().driver.SetText(rex::SettingLayer::kTitle, "none"));
        return rex::Ok();
    }
private:
    TitleRuntime title_;
};

int main_preflight(MetroPreflight& app, const rex::CLIArgList& args) {
    if (!app.Init(args)) {
        fail("host_init");
        app.Shutdown();
        return 1;
    }
    const bool ok = app.Check();
    app.Release();
    const int status = app.Shutdown();
    if (ok && status == 0) {
        std::cout << "METRO_PREFLIGHT pass clean_unload" << std::endl;
        return 0;
    }
    return 1;
}
}
int MetroHostEntry(const rex::CLIArgList& args) {
    const char* boot = std::getenv("X360_METRO_BOOT");
    if (boot && std::string_view(boot) == "1") return metro_boot::run(args);
    MetroPreflight app;
    return main_preflight(app, args);
}
REX_DETAIL_ENTRY_POINTS(MetroHostEntry)
