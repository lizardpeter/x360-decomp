#pragma once
// Opt-in diagnostic boot using the original native XAM and dashboard entries.
#include <rex/app/title_app.h>
#include <rex/kernel/function_dispatcher.h>
#include <rex/kernel/object/kernel_thread.h>
#include <rex/kernel/object/event_object.h>
#include <rex/gpu/graphics_system.h>
#include <rex/filesystem/file_system.h>
#include <rex/path_settings.h>
#include <filesystem>
#include <atomic>
#include <iostream>
#include <iomanip>
#include <rex/kernel/guest_memory.h>
#include <rex/ppc/context.h>
#include <rex/kernel/module.h>
#include <stdexcept>
#include "metro_preflight_bindings.hpp"
#include "metro_retail_bindings.hpp"
#include "metro_kernel_variables.hpp"
#include "metro_bootanim_mapping.hpp"
#include <rex/kernel/thread_registry.h>
#include <chrono>
#include <cstdlib>
#include <string_view>

namespace metro_boot {
inline constexpr char kXamPath[] = "game:\\xam.xex";

// LoadFromFile stores the canonical filesystem path rather than the input
// alias. GetModule resolves the alias through Stat before searching the user
// registry; user_only keeps the hosted kernel XAM out of this lookup.
inline auto find_retail_xam(rex::kernel::IModuleRegistry& registry) {
    return registry.GetModule(kXamPath, true);
}


// Keep the writable dashboard cache separate from the verified read-only
// firmware tree. Use the SDK's existing symbolic-link routing rather than
// changing mount precedence or enabling writes to the original title.
inline bool mount_writable_area(rex::kernel::TitleRuntime& title, const char* folder,
                                const char* device, const char* alias) {
    namespace fs = std::filesystem;
    namespace vfs = rex::filesystem;
    const auto user_root = REX_PATHS().user_root.Get();
    if (user_root.empty()) return false;
    std::error_code ec;
    const auto input = fs::weakly_canonical(title.GetTitlePaths().game_root.Get(), ec);
    if (ec || input.empty()) return false;
    const auto cache = fs::weakly_canonical(user_root / "metro-17559" / folder, ec);
    if (ec || cache.empty()) return false;
    auto contains = [](const fs::path& parent, const fs::path& child) {
        auto p=parent.begin(), c=child.begin();
        for (; p!=parent.end(); ++p,++c)
            if (c==child.end() || *p!=*c) return false;
        return true;
    };
    if (contains(input,cache) || contains(cache,input)) return false;
    fs::create_directories(cache,ec);
    if (ec || !fs::is_directory(cache,ec) || ec) return false;
    auto& mounts=title.GetFileSystem();
    if (!mounts.Mount({device, vfs::ProviderType::kHostDirectory,
                       cache, vfs::MountFlags::kWritable, {}})) return false;
    if (!mounts.Link(alias,device)) return false;
    return bool(mounts.Stat(alias));
}

inline bool mount_hdd_cache(rex::kernel::TitleRuntime& title) {
    return mount_writable_area(title,"hdd-cache","\\Device\\MetroHddCache",
                               "\\Device\\Harddisk0\\Partition1\\Cache") &&
           bool(title.GetFileSystem().Stat("game:\\Cache"));
}

inline bool mount_dashboard_user(rex::kernel::TitleRuntime& title) {
    // Per-installation dashboard state: no invented theme or vision files.
    return mount_writable_area(title,"dashboard-user","\\Device\\MetroDashUser","DASHUSER:");
}

inline bool mount_local_profiles(rex::kernel::TitleRuntime& title) {
    // Opt-in only: the source package is never mounted. The staging tool
    // creates an isolated copy under the same per-installation user root.
    // This makes the Content directory addressable, not an invented
    // physical storage device or a synthetic signed-in profile.
    const auto root=REX_PATHS().user_root.Get()/"metro-17559"/"profile-storage"/"Content";
    std::error_code ec;
    if (!std::filesystem::is_directory(root,ec) || ec) return false;
    return mount_writable_area(title,"profile-storage/Content","\\Device\\MetroProfileContent",
                               "\\Device\\Harddisk0\\Partition1\\Content");
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

// Explicit capability experiment. This is a hosted kernel variable, not an
// alteration of the retail XAM image or its privilege/Guide-disabled checks.
inline bool guide_hardware_experiment(rex::kernel::TitleRuntime& title) {
    const char* setting=std::getenv("X360_METRO_GUIDE_UI");
    if (!setting || std::string_view(setting)=="0") return true;
    if (std::string_view(setting)!="1") return false;
    const auto kernel=title.GetModuleRegistry().FindKernelModule("xboxkrnl");
    if (!kernel) return false;
    auto object=title.GetObjectTable().Get<rex::kernel::ModuleObject>(*kernel);
    if (!object) return false;
    auto& memory=title.GetGuestMemory();
    const auto target=object->GetVariable(0x156);
    const auto slot=memory.Load<rex::be_u32>(0x815F0480u);
    if (!target || !slot || static_cast<rex::u32>(*slot)!=target) return false;
    const auto before=memory.Load<rex::be_u32>(target);
    if (!before || static_cast<rex::u32>(*before)!=0x20u) return false;
    if (!memory.Store(target,rex::be_u32(0x220u))) return false;
    const auto after=memory.Load<rex::be_u32>(target);
    if (!after || static_cast<rex::u32>(*after)!=0x220u) return false;
    std::cout<<"METRO_GUIDE_HW original=0x20 hosted=0x220 diagnostic=1"<<std::endl;
    return true;
}

// Exercise the original four-instruction, stackless XAM leaf on the actual
// native DLL, not a synthetic function or an OS mapping-only test.
inline bool prepare_hosted_heap_flag(rex::kernel::TitleRuntime& title) {
    const auto leaf=title.FindFunction(0x8168AF28u);
    if (!leaf || !title.PrepareHostedXamHeapFlag()) return false;
    PPCContext ctx{};
    ctx.r3.u64=0xFFFFFFFFu;
    (*leaf)(ctx,title.GetMembase().GetBase());
    if (ctx.r3.u32!=0) return false;
    std::cout<<"METRO_HOSTED_HEAP_FLAG native_original_leaf=8168AF28 result=0"<<std::endl;
    return true;
}

struct EntryBinding {
    PPCFunc* dashboard{};
    rex::kernel::FunctionDispatcher* dispatcher{};
    std::uint32_t xam_handle{};
    std::uint32_t intro_handle{};
    PPCFunc* intro_control{};
};
inline EntryBinding entry;
inline std::atomic<bool> attached{false};
inline std::atomic<bool> intro_entered{false},intro_returned{false};
// 0 not requested, 1 dispatched, 2 original control returned, 3 failed,
// 4 original animation returned before control could be claimed.
inline std::atomic<unsigned> intro_control_state{0};

// Argument 0 arms flag B. Original 9800EA10 then checks its own
// phase and animation conditions before setting flag A and exiting.
// This hosted event-driven policy is not yet a recovered kernel caller.
inline void intro_control(PPCContext& ctx,rex::u8* base) {
    auto* thread=rex::kernel::KernelThread::GetCallingThread();
    if (!thread || !entry.intro_control || ctx.r3.u32!=0) {
        std::cout<<"METRO_INTRO fail control_binding"<<std::endl;
        intro_control_state.store(3,std::memory_order_release);
        intro_control_state.notify_all();
        if (thread)thread->Exit(1);
        return;
    }
    auto& mem=thread->GetRuntime().GetGuestMemory();
    const auto before=mem.Load<rex::u8>(metro_intro::kControlFlagB);
    entry.intro_control(ctx,base);
    const auto after=mem.Load<rex::u8>(metro_intro::kControlFlagB);
    if (!before || !after || *after!=1) {
        std::cout<<"METRO_INTRO fail original_control_flag"<<std::endl;
        intro_control_state.store(3,std::memory_order_release);
        intro_control_state.notify_all();
        thread->Exit(1);
        return;
    }
    std::cout<<"METRO_INTRO pass control_return argument=0 flag_b="
             <<unsigned(*after)<<std::endl;
    intro_control_state.store(2,std::memory_order_release);
    intro_control_state.notify_all();
    ctx.r3.u64=0;
}

inline void startup(PPCContext& ctx, rex::u8* base) {
    auto* thread = rex::kernel::KernelThread::GetCallingThread();
    if (!thread || !thread->IsMainThread() || !entry.dashboard ||
        !entry.dispatcher || !entry.xam_handle)
        throw std::runtime_error("missing Metro guest startup binding");
    std::cout << "METRO_BOOT pass guest_thread" << std::endl;
    if (entry.intro_handle) {
        // Execute saves and restores the caller's full guest register context.
        // Original animation and dashboard use the SAME runtime and graphics
        // device. Keep the entryless module mapped until normal runtime unload.
        rex::u64 args[]={entry.intro_handle,0};
        intro_entered.store(true,std::memory_order_release);
        std::cout<<"METRO_INTRO original_entry flags=0"<<std::endl;
        const auto result=entry.dispatcher->Execute(thread->GetThreadState(),
            metro_intro::kStart,args,2);
        intro_returned.store(true,std::memory_order_release);
        std::cout<<"METRO_INTRO original_return result=0x"<<std::hex<<result<<std::dec<<std::endl;
        // Join the actual control publication, not a timed sleep loop.
        // A naturally completed original run need not have a control task.
        unsigned idle=0;
        intro_control_state.compare_exchange_strong(idle,4,std::memory_order_acq_rel);
        unsigned state=intro_control_state.load(std::memory_order_acquire);
        while (state==1) {
            intro_control_state.wait(state,std::memory_order_acquire);
            state=intro_control_state.load(std::memory_order_acquire);
        }
        if (result!=0 || state==3) {
            std::cout<<"METRO_INTRO fail original_completion"<<std::endl;
            thread->Exit(1);
        }
        std::cout<<"METRO_INTRO pass original_completion"<<std::endl;
    }
    // XAM is a system DLL. Its original initializer explicitly chooses
    // a different heap for system and title threads. Run attach with the
    // actual system KPROCESS/TLS, not a forced return from a kernel export.
    std::cout << "METRO_BOOT xam_attach_begin" << std::endl;
    auto attached_xam=thread->GetRuntime().AttachHostedSystemModule(kXamEntry,entry.xam_handle);
    if (!attached_xam) {
        std::cout << "METRO_BOOT fail system_attach " << attached_xam.error().GetDescription() << std::endl;
        thread->Exit(1);
    }
    const auto result=attached_xam->entry_result;
    auto& memory=thread->GetRuntime().GetGuestMemory();
    auto object=memory.Load<rex::be_u32>(0x81A9F850);
    std::cout << "METRO_BOOT system_object=0x" << std::hex
              << (object ? static_cast<rex::u32>(*object) : 0u)
              << " readable=" << static_cast<bool>(object) << std::dec << std::endl;
    std::cout << "METRO_BOOT xam_attach_result=0x" << std::hex << result << std::dec << std::endl;
    if (static_cast<std::uint32_t>(result) == 0 || result == 0xDEADBABE) {
        std::cout << "METRO_BOOT fail xam_attach" << std::endl;
        thread->Exit(1);
    }
    const auto bound_pads=attached_xam->bound_pads;
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
        intro_entered=false;intro_returned=false;intro_control_state=0;
        const char* option=std::getenv("X360_METRO_INTRO");
        const bool with_intro=option && std::string_view(option)=="1";
        auto& paths = title.GetTitlePaths();
        if (paths.game_root.Get().empty() || paths.entry.Get() != "dash.xex" ||
            paths.game_writable.Get()) return fail("input_settings");
        if (!mount_flash(title)) return fail("flash_mount");
        std::cout << "METRO_BOOT pass flash_mount" << std::endl;
        if (!mount_hdd_cache(title)) return fail("hdd_cache_mount");
        std::cout << "METRO_BOOT pass hdd_cache_mount" << std::endl;
        if (!mount_dashboard_user(title)) return fail("dashboard_user_mount");
        std::cout << "METRO_BOOT pass dashboard_user_mount" << std::endl;
        const char* profiles=std::getenv("X360_METRO_LOCAL_PROFILES");
        if(profiles && std::string_view(profiles)=="1") {
            if(!mount_local_profiles(title))return fail("local_profile_content_mount");
            std::cout<<"METRO_PROFILE content_mount=ready signin_verified=0"<<std::endl;
        }
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
        if (!prepare_hosted_heap_flag(title)) return fail("hosted_heap_flag");
        if (!guide_hardware_experiment(title)) return fail("guide_hardware_experiment");
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
        if (with_intro) {
            if (!metro_intro::load(title,&entry.intro_handle))return fail("intro_mapping");
            auto control=title.FindFunction(metro_intro::kControl);
            if (!control || *control==&intro_control ||
                !title.GetGuestMemory().GetWritableSpan(metro_intro::kControlFlagA,2))
                return fail("intro_control_mapping");
            entry.intro_control=*control;
            if (!dispatcher->SetFunction(metro_intro::kControl,&intro_control))
                return fail("intro_control_install");
            // Hosted diagnostic reserves the minimum tested intro stack.
            // Never alter the on-disk dashboard XEX or its actual entry.
            if (dash->user.stack_size<256u*1024u)dash->user.stack_size=256u*1024u;
            std::cout<<"METRO_INTRO pass prepared diagnostic_flags=0"<<std::endl;
        }
        if (!dispatcher->SetFunction(kDashEntry, &startup)) return fail("entry_install");
        std::cout << "METRO_BOOT pass mapped" << std::endl;
        return rex::Ok();
    }
    void OnRun() override {
        std::uint64_t dash_reported=0, intro_baseline=0, intro_reported=0, dash_baseline=0;
        bool intro_seen=false, dash_seen=false;
        while (RunFrame()) {
            const auto frames = GetGraphics().GetFrameStats().frame_count;
            if (intro_entered.load(std::memory_order_acquire) &&
                !intro_returned.load(std::memory_order_acquire)) {
                if (!intro_seen) {intro_seen=true;intro_baseline=frames;}
                const auto intro_frames=frames>=intro_baseline?frames-intro_baseline:0;
                if (intro_frames>intro_reported) {
                    intro_reported=intro_frames;
                    std::cout<<"METRO_INTRO frames "<<intro_frames<<std::endl;
                }
                // Observe only an existing original notification event.
                // Do not create, reset or consume a synchronization event.
                // Frame counts are telemetry, never a completion predicate.
                auto& runtime=GetTitleRuntime();
                if (intro_control_state.load(std::memory_order_acquire)==0) {
                    rex::kernel::Pinned<rex::kernel::EventObject> ready(
                        runtime.GetObjectTable().GetByAddress(metro_intro::kInitialUpdateEvent));
                    rex::u32 signaled=0;
                    if (ready && ready->manual_reset.load(std::memory_order_acquire))
                        ready->Query(nullptr,&signaled);
                    unsigned expected=0;
                    if (signaled && !intro_returned.load(std::memory_order_acquire) &&
                        intro_control_state.compare_exchange_strong(expected,1,std::memory_order_acq_rel)) {
                        std::cout<<"METRO_INTRO original_initial_update_event signaled"<<std::endl;
                        auto control=runtime.GetThreadRegistry().CreateTaskThread(metro_intro::kControl,0);
                        if (!control) {
                            intro_control_state.store(3,std::memory_order_release);
                            intro_control_state.notify_all();
                            std::cout<<"METRO_INTRO fail control_thread_launch"<<std::endl;
                            rex::app::RequestShutdown(1);
                        } else rex::kernel::CloseOwned(runtime.GetObjectTable(),*control);
                    }
                }
            }
            if (attached.load(std::memory_order_acquire) && !dash_seen) {
                dash_seen=true;dash_baseline=frames;
                std::cout<<"METRO_BOOT dashboard_frame_baseline "<<dash_baseline<<std::endl;
            }
            if (dash_seen && frames<dash_baseline) {
                // A driver reset creates a new counter generation. Do not
                // subtract across generations or recycle the intro count.
                dash_baseline=frames;dash_reported=0;
                std::cout<<"METRO_BOOT dashboard_frame_reset "<<frames<<std::endl;
            }
            if (dash_seen) {
                const auto dash_frames=frames-dash_baseline;
                if (dash_frames>0 && (dash_reported==0 || dash_frames>=dash_reported+5)) {
                    dash_reported=dash_frames;
                    if(entry.intro_handle)
                        std::cout<<"METRO_INTRO post_handoff_frames "<<dash_frames<<std::endl;
                    std::cout<<"METRO_BOOT frames "<<dash_frames<<std::endl;
                }
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
