#pragma once
// Opt-in diagnostic boot using the original native XAM and dashboard entries.
#include <rex/app/title_app.h>
#include <rex/kernel/function_dispatcher.h>
#include <rex/kernel/object/kernel_thread.h>
#include <rex/gpu/graphics_system.h>
#include <rex/filesystem/file_system.h>
#include <atomic>
#include <iostream>
#include <stdexcept>
#include "metro_preflight_bindings.hpp"

namespace metro_boot {
inline constexpr char kXamPath[] = "game:\\xam.xex";

// LoadFromFile stores the canonical filesystem path rather than the input
// alias. GetModule resolves the alias through Stat before searching the user
// registry; user_only keeps the hosted kernel XAM out of this lookup.
inline auto find_retail_xam(rex::kernel::IModuleRegistry& registry) {
    return registry.GetModule(kXamPath, true);
}

inline bool mount_flash(rex::kernel::TitleRuntime& title) {
    auto& fs = title.GetFileSystem();
    const auto root = title.GetTitlePaths().game_root.Get() / "flash";
    // Diagnostic mount from the verified PIRS flash-member names.
    // Never expose arbitrary host files or make the original resources writable.
    if (!fs.Mount({"\\Device\\Flash", rex::filesystem::ProviderType::kHostDirectory,
                   root, rex::filesystem::MountFlags::kNone, {}}))
        return false;
    if (!fs.Link("flash:", "\\Device\\Flash"))
        return false;
    return bool(fs.Stat("flash:\\dash.xex")) &&
           bool(fs.Stat("flash:\\xam.xex")) &&
           bool(fs.Stat("flash:\\shrdres.xzp"));
}

struct EntryBinding {
    PPCFunc* dashboard{};
    rex::kernel::FunctionDispatcher* dispatcher{};
    std::uint32_t xam_handle{};
};
inline EntryBinding entry;
inline std::atomic<bool> attached{false};

inline void startup(PPCContext& ctx, rex::u8* base) {
    auto* thread = rex::kernel::KernelThread::GetCallingThread();
    if (!thread || !thread->IsMainThread() || !entry.dashboard ||
        !entry.dispatcher || !entry.xam_handle)
        throw std::runtime_error("missing Metro guest startup binding");
    std::cout << "METRO_BOOT pass guest_thread" << std::endl;
    // Use the real process-attach ABI and preserve the result.
    rex::u64 args[] = {entry.xam_handle, 1, 0};
    const auto result = entry.dispatcher->Execute(thread->GetThreadState(), kXamEntry, args, 3);
    if (static_cast<std::uint32_t>(result) == 0 || result == 0xDEADBABE) {
        std::cout << "METRO_BOOT fail xam_attach" << std::endl;
        thread->Exit(1);
    }
    attached.store(true, std::memory_order_release);
    std::cout << "METRO_BOOT pass xam_attach\nMETRO_BOOT pass dashboard_entry" << std::endl;
    entry.dashboard(ctx, base);
}

class App final : public rex::app::TitleApp {
public:
    App() : TitleApp("metro_boot", kPPCImageConfig) {}
protected:
    rex::Result<void> OnTitleLaunch(rex::kernel::TitleRuntime& title) override {
        auto fail = [](const char* stage) -> rex::Result<void> {
            std::cout << "METRO_BOOT fail " << stage << std::endl;
            return rex::Err(rex::ErrorCategory::kRuntime, stage);
        };
        entry = {};
        attached.store(false, std::memory_order_relaxed);
        auto& paths = title.GetTitlePaths();
        if (paths.game_root.Get().empty() || paths.entry.Get() != "dash.xex" ||
            paths.game_writable.Get()) return fail("input_settings");
        if (!mount_flash(title)) return fail("flash_mount");
        std::cout << "METRO_BOOT pass flash_mount" << std::endl;
        auto& registry = title.GetModuleRegistry();
        const auto executable = registry.GetExecutable();
        if (!executable) return fail("dashboard_handle");
        auto dash = title.GetObjectTable().Get<rex::kernel::ModuleObject>(*executable);
        auto* dx = dash ? dash->GetXEX() : nullptr;
        if (!dx || dx->GetBaseAddress() != kDashBase || dx->GetImageSize() != kDashSize ||
            dx->GetEntryPoint() != kDashEntry) return fail("dashboard_identity");
        if (find_retail_xam(registry)) return fail("unexpected_preloaded_xam");
        const auto loaded = registry.LoadUserModule(kXamPath, false);
        if (!loaded || !*loaded) return fail("xam_load");
        const auto user = find_retail_xam(registry);
        const auto by_name = registry.FindUserModule("xam.xex");
        if (!user || *user != *loaded || !by_name || *by_name != *loaded)
            return fail("xam_registry");
        const auto kernel = registry.FindKernelModule("xam");
        if (!kernel || *kernel == *loaded) return fail("xam_isolation");
        auto xam = title.GetObjectTable().Get<rex::kernel::ModuleObject>(*loaded);
        auto* xx = xam ? xam->GetXEX() : nullptr;
        if (!xx || xx->GetBaseAddress() != kXamBase || xx->GetImageSize() != kXamSize ||
            xx->GetEntryPoint() != kXamEntry || !xam->user.is_dll_module ||
            !xam->hmodule_ptr || !title.FindFunction(kXamEntry)) return fail("xam_identity");
        for (const auto& b : kBindings) {
            const auto value = title.GetGuestMemory().Load<rex::be_u32>(b.value_slot);
            if (xx->GetExportAddress(b.ordinal) != b.target ||
                !title.FindFunction(b.thunk) || !title.FindFunction(b.target) ||
                !value || static_cast<rex::u32>(*value) != b.thunk)
                return fail("export_mapping");
        }
        const auto original = title.FindFunction(kDashEntry);
        auto* dispatcher = dx->GetFunctionDispatcher();
        if (!original || !dispatcher || *original == &startup) return fail("entry_binding");
        entry = {*original, dispatcher, xam->hmodule_ptr};
        if (!dispatcher->SetFunction(kDashEntry, &startup)) return fail("entry_install");
        std::cout << "METRO_BOOT pass mapped" << std::endl;
        return rex::Ok();
    }
    void OnRun() override {
        std::uint64_t reported = 0;
        while (RunFrame()) {
            const auto frames = GetGraphics().GetFrameStats().frame_count;
            if (attached.load(std::memory_order_acquire) &&
                frames > 0 && (reported == 0 || frames >= reported + 60)) {
                reported = frames;
                std::cout << "METRO_BOOT frames " << frames << std::endl;
            }
        }
    }
    void OnTitleExit(rex::kernel::TitleExitReason) override {
        std::cout << "METRO_BOOT guest_exit" << std::endl;
        rex::app::RequestShutdown(1);
    }
};

inline int run(const rex::CLIArgList& args) {
    App app;
    if (app.Init(args) && app.LaunchTitle()) app.Run();
    return app.Shutdown();
}
}
