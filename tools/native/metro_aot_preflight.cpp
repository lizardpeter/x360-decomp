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

        auto& registry = title_.GetModuleRegistry();
        const auto exe = registry.GetExecutable();
        if (!exe)
            return fail("dashboard_handle");
        auto dash = title_.GetObjectTable().Get<ModuleObject>(*exe);
        const auto* dash_xex = dash ? dash->GetXEX() : nullptr;
        if (!dash_xex || dash_xex->GetBaseAddress() != kDashBase ||
            dash_xex->GetImageSize() != kDashSize ||
            dash_xex->GetEntryPoint() != kDashEntry ||
            !title_.FindFunction(kDashEntry))
            return fail("dashboard_identity");

        // The SDK's built-in hosted XAM is not the retail XAM user module.
        // Map the separately generated native library through the existing loader.
        // false explicitly prevents DLL_PROCESS_ATTACH / guest execution.
        if (registry.FindUserModule("game:\\xam.xex"))
            return fail("unexpected_preloaded_xam");
        const auto loaded = registry.LoadUserModule("game:\\xam.xex", false);
        if (!loaded)
            return fail("xam_load");
        const auto user = registry.FindUserModule("game:\\xam.xex");
        if (!user || *user != *loaded)
            return fail("xam_registry");
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

        for (const auto& binding : kBindings) {
            // Check the original export and both registered function addresses.
            // Do not invoke either function or call an unverified export resolver.
            if (xam->GetExportAddress(binding.ordinal) != binding.target ||
                !xam->IsExecutableAddress(binding.target))
                return fail("xam_export_identity");
            if (!title_.FindFunction(binding.thunk))
                return fail("dashboard_thunk_registration");
            if (!title_.FindFunction(binding.target))
                return fail("xam_export_registration");
            const auto value = title_.GetGuestMemory().Load<rex::be_u32>(binding.value_slot);
            if (!value || static_cast<rex::u32>(*value) != binding.thunk)
                return fail("dashboard_import_value");
        }
        if (title_.IsRunning())
            return fail("unexpected_guest_launch");
        std::cout << "METRO_PREFLIGHT pass five_export_mappings" << std::endl;
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
