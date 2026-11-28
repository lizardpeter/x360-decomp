// Isolated original-animation launch, using the actual native compiled module.
// No dashboard code, substitute media, or modified original XEX headers.
#include <rex/app/title_app.h>
#include <rex/apu/audio_system.h>
#include <rex/gpu/graphics_system.h>
#include <rex/kernel/function_dispatcher.h>
#include <rex/kernel/guest_memory.h>
#include <rex/kernel/module.h>
#include <rex/kernel/object/kernel_thread.h>
#include <rex/kernel/object/event_object.h>
#include <rex/kernel/object/module_object.h>
#include <rex/kernel/object/object_table.h>
#include <rex/kernel/title_paths.h>
#include <rex/kernel/thread_registry.h>
#include <rex/ppc/image.h>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string_view>
#include "metro_bootanim_live_proofs.hpp"

extern "C" const rex::ppc::PPCImage* ReXGetModuleImage();

namespace {
constexpr rex::u32 kStart=0x98020E60u;
PPCFunc* original_start{};
PPCFunc* original_control{};
constexpr rex::u32 kControl=0x98020EC8u;
constexpr rex::u32 kControlFlagA=0x98077760u,kControlFlagB=0x98077761u;
constexpr rex::u32 kInitialUpdateEvent=0x980590BCu;
// 0 idle, 1 claimed, 2 original control returned, 3 failed, 4 naturally completed.
std::atomic<unsigned> control_state{0};
std::unique_ptr<rex::platform::Event> control_completion;
void finish_control(unsigned state) {
    control_state.store(state,std::memory_order_release);
    if(control_completion)control_completion->Set();
}
rex::u32 guest_module{};
std::atomic<bool> original_entered{false},original_returned{false};

void launch_original(PPCContext& ctx,rex::u8* base) {
    auto* thread=rex::kernel::KernelThread::GetCallingThread();
    if (!thread || !thread->IsMainThread() || !original_start || !guest_module) {
        std::cout<<"BOOTANIM_LIVE fail guest_entry_binding"<<std::endl;
        if (thread) thread->Exit(1);
        return;
    }
    // Verified first-export contract: r3=real guest HMODULE, r4=flags.
    // Zero is an explicitly selected diagnostic profile, not the recovered
    // retail kernel policy. It chooses the animated branch, not display-off.
    ctx.r3.u64=guest_module;
    ctx.r4.u64=0;
    original_entered.store(true,std::memory_order_release);
    std::cout<<"BOOTANIM_LIVE original_entry hmodule=0x"<<std::hex<<guest_module
             <<" flags=0x0"<<std::dec<<std::endl;
    original_start(ctx,base);
    original_returned.store(true,std::memory_order_release);
    std::cout<<"BOOTANIM_LIVE original_return r3=0x"<<std::hex<<ctx.r3.u32<<std::dec<<std::endl;
    unsigned idle=0;
    control_state.compare_exchange_strong(idle,4,std::memory_order_acq_rel);
    unsigned state=control_state.load(std::memory_order_acquire);
    if(state==1) {
        const auto wait=thread->GetRuntime().GetThreadRegistry().GetObjectWaiter().WaitHostObject(
            control_completion.get(),std::chrono::milliseconds::max());
        state=control_state.load(std::memory_order_acquire);
        if(wait!=rex::platform::WaitResult::kSuccess || state!=2)state=3;
    }
    if(ctx.r3.u32!=0 || state==3) {
        finish_control(3);
        thread->Exit(1);
    }
}

// Run the original second export on a real guest thread. Its two branches
// publish different byte flags. Never write either flag from the host.
void run_control(PPCContext& ctx,rex::u8* base) {
    auto* thread=rex::kernel::KernelThread::GetCallingThread();
    if (!thread || !original_control || ctx.r3.u32!=0) {
        std::cout<<"BOOTANIM_LIVE fail control_thread_binding"<<std::endl;
        finish_control(3);
        if (thread)thread->Exit(1);
        return;
    }
    const auto argument=ctx.r3.u32;
    auto& memory=thread->GetRuntime().GetGuestMemory();
    auto a=memory.Load<rex::u8>(kControlFlagA);
    auto b=memory.Load<rex::u8>(kControlFlagB);
    if (!a || !b) {
        std::cout<<"BOOTANIM_LIVE fail control_flags_unmapped"<<std::endl;
        finish_control(3);
        thread->Exit(1);
    }
    std::cout<<"BOOTANIM_LIVE control_begin argument="<<argument
             <<" flag_a="<<unsigned(*a)<<" flag_b="<<unsigned(*b)<<std::endl;
    original_control(ctx,base);
    a=memory.Load<rex::u8>(kControlFlagA);
    b=memory.Load<rex::u8>(kControlFlagB);
    if (!a || !b || *b!=1) {
        std::cout<<"BOOTANIM_LIVE fail control_flag_publication"<<std::endl;
        finish_control(3);
        thread->Exit(1);
    }
    std::cout<<"BOOTANIM_LIVE control_return argument="<<argument
             <<" flag_a="<<unsigned(*a)<<" flag_b="<<unsigned(*b)<<std::endl;
    finish_control(2);
    ctx.r3.u64=0;
}

class BootanimLive final : public rex::app::TitleApp {
public:
    BootanimLive():TitleApp("metro_bootanim_live",*ReXGetModuleImage()) {}
protected:
    rex::Result<void> OnTitleLaunch(rex::kernel::TitleRuntime& title) override {
        auto fail=[](const char* stage)->rex::Result<void>{
            std::cout<<"BOOTANIM_LIVE fail "<<stage<<std::endl;
            return rex::Err(rex::ErrorCategory::kRuntime,stage);
        };
        const char* opt=std::getenv("X360_BOOTANIM_FLAGS");
        if (!opt || std::string_view(opt)!="0")return fail("explicit_diagnostic_flags");
        auto& paths=title.GetTitlePaths();
        if (paths.entry.Get()!="bootanim.xex" || paths.game_root.Get().empty() ||
            paths.game_writable.Get()) return fail("input_settings");
        original_start=nullptr;original_control=nullptr;guest_module=0;
        original_entered=false;original_returned=false;control_state=0;
        control_completion.reset();
        const char* control=std::getenv("X360_BOOTANIM_CONTROL");
        diagnostic_control_=control && std::string_view(control)=="graceful_event";
        if(diagnostic_control_) {
            control_completion=rex::platform::Event::CreateManualResetEvent(false);
            if(!control_completion)return fail("control_completion_event");
        }
        auto& registry=title.GetModuleRegistry();
        const auto exe=registry.GetExecutable();
        if (!exe)return fail("module_handle");
        auto object=title.GetObjectTable().Get<rex::kernel::ModuleObject>(*exe);
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
        std::cout<<"BOOTANIM_LIVE pass identity_and_exports"<<std::endl;
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
                std::cout<<"BOOTANIM_LIVE unresolved ordinal=0x"<<std::hex<<proof.ordinal
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
        std::cout<<"BOOTANIM_LIVE imports functions="<<functions<<" variables="<<variables
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
        std::cout<<"BOOTANIM_LIVE pass original_audio bytes="<<size<<std::endl;
        auto function=title.FindFunction(kStart);
        auto* dispatcher=xex->GetFunctionDispatcher();
        if (!function || !dispatcher || *function==&launch_original)return fail("entry_dispatch");
        original_start=*function;guest_module=object->hmodule_ptr;
        if (!dispatcher->SetFunction(kStart,&launch_original))return fail("entry_install");
        if (diagnostic_control_) {
            auto control=title.FindFunction(kControl);
            if (!control || *control==&run_control ||
                !mem.GetWritableSpan(kControlFlagA,2))return fail("control_export_mapping");
            original_control=*control;
            if (!dispatcher->SetFunction(kControl,&run_control))return fail("control_install");
            std::cout<<"BOOTANIM_LIVE diagnostic_control graceful_event"<<std::endl;
        }
        // Select the verified export for this isolated TitleRuntime launch,
        // not a fabricated XEX entrypoint. No guest image/header is altered.
        object->user.entry_point=kStart;
        if (!object->user.stack_size) object->user.stack_size=256*1024;
        std::cout<<"BOOTANIM_LIVE pass mapped original_xex_entry=0 diagnostic_launch_export=1"
                 <<" stack_bytes="<<object->user.stack_size<<std::endl;
        return rex::Ok();
    }
    void OnRun() override {
        std::uint64_t last=0;
        while (RunFrame()) {
            const auto frames=GetGraphics().GetFrameStats().frame_count;
            // The isolated path now exercises precisely the same original
            // readiness/phase contract as the integrated path. A frame
            // count is telemetry only; no force-exit control is issued.
            if (diagnostic_control_ && control_state.load(std::memory_order_acquire)==0 &&
                original_entered.load(std::memory_order_acquire) &&
                !original_returned.load(std::memory_order_acquire)) {
                auto& runtime=GetTitleRuntime();
                rex::kernel::Pinned<rex::kernel::EventObject> ready(
                    runtime.GetObjectTable().GetByAddress(kInitialUpdateEvent));
                rex::u32 signaled=0;
                if (ready && ready->manual_reset.load(std::memory_order_acquire))
                    ready->Query(nullptr,&signaled);
                unsigned idle=0;
                if (signaled && !original_returned.load(std::memory_order_acquire) &&
                    control_state.compare_exchange_strong(idle,1,std::memory_order_acq_rel)) {
                    std::cout<<"BOOTANIM_LIVE original_initial_update_event signaled"<<std::endl;
                    auto result=runtime.GetThreadRegistry().CreateTaskThread(kControl,0);
                    if (!result) {
                        std::cout<<"BOOTANIM_LIVE fail control_thread_launch "
                                 <<result.error().GetDescription()<<std::endl;
                        finish_control(3);
                        rex::app::RequestShutdown(1);
                    } else {
                        rex::kernel::CloseOwned(runtime.GetObjectTable(),*result);
                    }
                }
            }
            if (original_entered.load(std::memory_order_acquire) && frames>last) {
                last=frames;
                if (frames<=10 || frames%5==0)
                    std::cout<<"BOOTANIM_LIVE presented_frames "<<frames<<std::endl;
            }
        }
    }
    void OnTitleExit(rex::kernel::TitleExitReason reason) override {
        std::cout<<"BOOTANIM_LIVE guest_exit original_returned="
                 <<original_returned.load(std::memory_order_acquire)<<std::endl;
        const unsigned state=control_state.load(std::memory_order_acquire);
        rex::app::RequestShutdown(reason==rex::kernel::TitleExitReason::kNormalExit &&
            original_returned.load() && state!=3 &&
            (!diagnostic_control_ || state==2 || state==4)?0:1);
    }
private:
    bool diagnostic_control_=false;
};
}
REX_TITLE_APP(BootanimLive)
