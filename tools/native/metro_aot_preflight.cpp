// Host-only mapping and dispatch preflight for the original Metro/XAM pair.
// This deliberately never launches the dashboard or executes XAM's entry point.
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
#include <string_view>
#include "generated/dash_17559_init.h"
#include "metro_preflight_bindings.hpp"
#include "metro_aot_boot.hpp"

namespace {
using rex::kernel::ModuleObject;
using rex::kernel::TitleRuntime;

bool fail(const char* stage) {
    std::cout << "METRO_PREFLIGHT fail " << stage << std::endl;
    return false;
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
