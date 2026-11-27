#pragma once
// Opt-in diagnostic boot using the original native XAM and dashboard entries.
#include <rex/app/title_app.h>
#include <rex/kernel/function_dispatcher.h>
#include <rex/kernel/object/kernel_thread.h>
#include <rex/gpu/graphics_system.h>
#include <rex/filesystem/file_system.h>
#include <atomic>
#include <iostream>
#include <iomanip>
#include <rex/kernel/guest_memory.h>
#include <rex/kernel/module.h>
#include <stdexcept>
#include "metro_preflight_bindings.hpp"
#include "metro_retail_bindings.hpp"
#include "metro_kernel_variables.hpp"

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
    // The original dashboard creates media: -> \SystemRoot itself.
    // Mount the verified flat flash tree at the physical system name.
    if (!fs.Mount({"\\SystemRoot", rex::filesystem::ProviderType::kHostDirectory,
                   root, rex::filesystem::MountFlags::kNone, {}}))
        return false;
    return bool(fs.Stat("flash:\\dash.xex")) &&
           bool(fs.Stat("flash:\\xam.xex")) &&
           bool(fs.Stat("flash:\\shrdres.xzp")) &&
           bool(fs.Stat("\\SystemRoot\\shrdres.xzp")) &&
           bool(fs.Stat("\\SystemRoot\\SegoeXbox-Light.xtt"));
}


// Bind only an exact recorded retail import to a verified mapped target.
// The read-only import page is restored after a normal loader relocation.
// Unexpected values or missing metadata fail closed, never fabricated.
inline bool verify_live_binding(rex::kernel::TitleRuntime& title,
                                const rex::kernel::XEXModule& dash,
                                const rex::kernel::XEXModule& xam,
                                const Binding& binding, bool data) {
    std::size_t matches = 0;
    for (const auto& library : dash.GetImportLibraries()) {
        if (library.name != "xam" || library.file_name != "xam.xex") continue;
        for (const auto& item : library.imports) {
            if (item.ordinal == binding.ordinal &&
                item.value_address == binding.value_slot &&
                item.thunk_address == binding.thunk) ++matches;
        }
    }
    const auto export_address = xam.GetExportAddress(binding.ordinal);
    auto& memory = title.GetGuestMemory();
    const auto current = memory.Load<rex::be_u32>(binding.value_slot);
    const auto expected = data ? binding.target : binding.thunk;
    std::cout << "METRO_BINDING ordinal=0x" << std::hex << binding.ordinal
              << " slot=0x" << binding.value_slot
              << " expected=0x" << expected
              << " actual=0x" << (current ? static_cast<rex::u32>(*current) : 0u)
              << " export=0x" << export_address
              << std::dec << " readable=" << static_cast<bool>(current)
              << " records=" << matches << " data=" << data << std::endl;
    if (!current) {
        std::cout << "METRO_BINDING read_error " << current.error().GetDescription()
                  << std::endl;
        return false;
    }
    if (matches != 1 || export_address != binding.target) return false;
    if (data) {
        if (xam.IsExecutableAddress(binding.target) ||
            !memory.GetWritableSpan(binding.target, sizeof(rex::u32))) return false;
    } else {
        if (!xam.IsExecutableAddress(binding.target) ||
            !title.FindFunction(binding.thunk) ||
            !title.FindFunction(binding.target)) return false;
    }
    const rex::u32 old = *current;
    if (old == expected) return true;
    // The hosted loader can leave verified imports unbound (observed zero in
    // the live 17559 preflight). Relocate that state as well as an original
    // descriptor or the SDK's exact missing-variable marker. This is after
    // validating the unique import metadata, exact retail export and mapped
    // function/data target above; never accept a conflicting nonzero pointer.
    const bool unbound = old == 0;
    const bool raw_record = (old & 0xFF00FFFFu) == binding.ordinal;
    const bool data_marker = data &&
        old == (0xD000BEEFu | (static_cast<rex::u32>(binding.ordinal) & 0xFFFu) << 16);
    if (!unbound && !raw_record && !data_marker) return false;
    std::cout << "METRO_BINDING pending_relocation ordinal=0x" << std::hex
              << binding.ordinal << " old=0x" << old
              << " target=0x" << expected << std::dec << std::endl;
    const bool writable = bool(memory.GetWritableSpan(binding.value_slot, sizeof(rex::u32)));
    if (!writable && !memory.Protect(binding.value_slot, sizeof(rex::u32),
                                    rex::kernel::GuestProtect::kReadWrite)) return false;
    const auto stored = memory.Store(binding.value_slot, rex::be_u32(expected));
    const bool restored = writable ||
        bool(memory.Protect(binding.value_slot, sizeof(rex::u32),
                            rex::kernel::GuestProtect::kReadOnly));
    if (!stored || !restored) return false;
    const auto reread = memory.Load<rex::be_u32>(binding.value_slot);
    if (!reread || static_cast<rex::u32>(*reread) != expected) return false;
    std::cout << "METRO_BINDING relocated ordinal=0x" << std::hex << binding.ordinal
              << std::dec << std::endl;
    return true;
}

// Validate the entire routing plan before invoking either original module.
// The five-entry baseline did not prove that the rest of the dashboard calls
// shared the same XAM instance. Report every missing mapping, not only the first.
inline bool verify_retail_routes(rex::kernel::TitleRuntime& title,
                                 const rex::kernel::XEXModule& dash,
                                 const rex::kernel::XEXModule& xam) {
    std::size_t passed=0, missing_thunk=0, missing_target=0, failed_binding=0;
    for (const auto& binding : kRetailFunctionBindings) {
        const bool thunk = bool(title.FindFunction(binding.thunk));
        const bool target = bool(title.FindFunction(binding.target));
        if (!thunk || !target) {
            missing_thunk += !thunk;
            missing_target += !target;
            std::cout << "METRO_RETAIL_MISSING ordinal=0x" << std::hex << binding.ordinal
                      << " thunk=0x" << binding.thunk << " target=0x" << binding.target
                      << std::dec << " thunk_mapped=" << thunk << " target_mapped=" << target << std::endl;
            continue;
        }
        if (verify_live_binding(title, dash, xam, binding, false)) ++passed;
        else ++failed_binding;
    }
    std::cout << "METRO_RETAIL_ROUTES passed=" << passed << " expected="
              << kRetailFunctionBindings.size() << " missing_thunk=" << missing_thunk
              << " missing_target=" << missing_target << " failed_binding=" << failed_binding << std::endl;
    return passed == kRetailFunctionBindings.size();
}

// Observe all original kernel data imports. Only a verified target can be
// relocated; no missing variable is supplied a fabricated value.
template<std::size_t N>
inline bool verify_kernel_variables(rex::kernel::TitleRuntime& title,
                                    const rex::kernel::XEXModule& image,
                                    const std::array<KernelVariableBinding,N>& bindings,
                                    const char* module) {
    const auto kernel=title.GetModuleRegistry().FindKernelModule("xboxkrnl");
    if (!kernel) return false;
    auto object=title.GetObjectTable().Get<rex::kernel::ModuleObject>(*kernel);
    if (!object) return false;
    auto& memory=title.GetGuestMemory();
    std::size_t passed=0, unknown=0, failures=0;
    for (const auto& binding:bindings) {
        std::size_t matches=0;
        for(const auto& library:image.GetImportLibraries()) {
            if(library.name!="xboxkrnl")continue;
            for(const auto& item:library.imports)
                if(item.ordinal==binding.ordinal && item.value_address==binding.slot &&
                    !item.thunk_address)++matches;
        }
        const auto target=object->GetVariable(binding.ordinal);
        auto actual=memory.Load<rex::be_u32>(binding.slot);
        const rex::u32 value=actual?static_cast<rex::u32>(*actual):0u;
        const rex::u32 marker=0xD000BEEFu | (static_cast<rex::u32>(binding.ordinal)<<16);
        const bool unresolved_value=actual && (!value || value==marker || (value&0xFF00FFFFu)==binding.ordinal);
        const bool verified=matches==1 && target && actual && bool(memory.Load<rex::be_u32>(target));
        if(verified && value!=target && unresolved_value) {
            const bool writable=bool(memory.GetWritableSpan(binding.slot,sizeof(rex::u32)));
            if(writable || memory.Protect(binding.slot,sizeof(rex::u32),rex::kernel::GuestProtect::kReadWrite)){
                const auto stored=memory.Store(binding.slot,rex::be_u32(target));
                const bool restored=writable || bool(memory.Protect(binding.slot,sizeof(rex::u32),rex::kernel::GuestProtect::kReadOnly));
                if(stored&&restored)actual=memory.Load<rex::be_u32>(binding.slot);
                else actual=memory.Load<rex::be_u32>(binding.slot); // still fail below if conflicting
                if(!stored||!restored){++failures;continue;}
            }
        }
        const bool valid=verified && actual && static_cast<rex::u32>(*actual)==target;
        // The original base-version value is not known. Keep its missing
        // state explicit, rather than treating it as a successful binding.
        const bool unresolved=matches==1 && !target && binding.ordinal==0x157 && unresolved_value;
        std::cout<<"METRO_KERNEL_VAR module="<<module<<" ordinal=0x"<<std::hex<<binding.ordinal
                 <<" slot=0x"<<binding.slot<<" target=0x"<<target
                 <<" actual=0x"<<(actual?static_cast<rex::u32>(*actual):0u)<<std::dec
                 <<" records="<<matches<<" state="<<(valid?"mapped":unresolved?"unknown_base_version":"invalid")
                 <<std::endl;
        if(valid)++passed;else if(unresolved)++unknown;else ++failures;
    }
    std::cout<<"METRO_KERNEL_VARS module="<<module<<" mapped="<<passed
             <<" unresolved="<<unknown<<" invalid="<<failures<<" expected="<<N<<std::endl;
    return failures==0 && passed+unknown==N;
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
    std::cout << "METRO_BOOT xam_attach_begin" << std::endl;
    const auto result = entry.dispatcher->Execute(thread->GetThreadState(), kXamEntry, args, 3);
    std::cout << "METRO_BOOT xam_attach_result=0x" << std::hex << result << std::dec << std::endl;
    if (static_cast<std::uint32_t>(result) == 0 || result == 0xDEADBABE) {
        std::cout << "METRO_BOOT fail xam_attach" << std::endl;
        thread->Exit(1);
    }
    const auto bound_pads = thread->GetRuntime().AnnounceHostedPads();
    std::cout << "METRO_BOOT hosted_pads=" << bound_pads << std::endl;
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
        if (!verify_kernel_variables(title,*dx,kDashKernelVariables,"dash") ||
            !verify_kernel_variables(title,*xx,kXamKernelVariables,"xam")) return fail("kernel_variables");
        if (!verify_retail_routes(title, *dx, *xx)) return fail("retail_export_mapping");
        if (!verify_live_binding(title, *dx, *xx, kXamDataBinding, true))
            return fail("data_mapping");
        if (!title.SelectRetailXam(*loaded) ||
            title.FindGuestModule("xam.xex") != *loaded ||
            title.FindGuestModule("flash:\\xam.xex") != *loaded ||
            registry.FindKernelModule("xam") != kernel) return fail("dynamic_xam_identity");
        std::cout << "METRO_BOOT pass dynamic_xam_identity" << std::endl;
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
