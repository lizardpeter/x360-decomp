#!/usr/bin/env python3
"""Package only native Windows build products, launchers and local input preparation."""
import argparse
import hashlib
import json
import shutil
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
REQUIRED={"dash_17559.exe","dash_17559_xam.dll","dash_17559_hud.dll","dash_17559_bootanim.dll",
          "rexbase.dll","rexppc.dll","rexkernel.dll","rexapp.dll","rexfilesystem.dll",
          "rexapu.dll","rexhid.dll","rexui.dll","rexgpu.dll","rexxam.dll",
          "rexgpu-xenos-vulkan.dll","rexapu-sdl3.dll","rexhid-sdl3.dll","rexui-sdl3.dll","sdl3.dll"}
PROFILE_DLLS={f"dash_17559_{name}.dll" for name in ("signin","deviceselector","vk","gamerprofile","createprofile")}
SUPPORT=("target.toml","tools/fetch_originals.py","tools/prepare_recompilation.py","tools/pirs.py",
         "tools/stage_dashboard_runtime.py","tools/prepare_windows_inputs.py","tools/stage_metro_profile.py","docs/native-offline-profiles.md","analysis/pirs_17559/members.json")
def pe_identity(path):
    with path.open("rb") as f:
        dos=f.read(64)
        if len(dos)!=64 or dos[:2]!=b"MZ":raise ValueError(f"not PE: {path.name}")
        offset=struct.unpack_from("<I",dos,60)[0]
        if not 64<=offset<=path.stat().st_size-26:raise ValueError("invalid PE offset")
        f.seek(offset);head=f.read(26)
    if head[:4]!=b"PE\0\0":raise ValueError("invalid PE signature")
    machine=struct.unpack_from("<H",head,4)[0]
    magic=struct.unpack_from("<H",head,24)[0]
    dll=bool(struct.unpack_from("<H",head,22)[0]&0x2000)
    if (machine,magic)!=(0x8664,0x20b) or dll!=(path.suffix.lower()==".dll"):
        raise ValueError(f"wrong PE architecture or kind: {path.name}")
    return {"machine":"AMD64","format":"PE32+","dll":dll}
def binary_files(folder,profile_modules=False):
    matches=list(folder.rglob("dash_17559.exe"))
    if len(matches)!=1:raise ValueError("expected exactly one native host executable")
    files=[p for p in matches[0].parent.iterdir() if p.is_file() and
           (p.name.lower()=="dash_17559.exe" or p.suffix.lower()==".dll")]
    names={p.name.lower() for p in files}
    if len(names)!=len(files):raise ValueError("duplicate binary names")
    if REQUIRED-names:raise ValueError("missing native dependencies: "+", ".join(sorted(REQUIRED-names)))
    present=names & PROFILE_DLLS
    if profile_modules and present!=PROFILE_DLLS:
        raise ValueError("missing original profile DLLs: "+", ".join(sorted(PROFILE_DLLS-present)))
    if not profile_modules and present:
        raise ValueError("unexpected original profile DLLs in baseline package")
    return sorted(files,key=lambda p:p.name.lower())
LAUNCH=r"""@echo off
setlocal
cd /d "%~dp0"
if not exist "inputs\dash.xex" goto missing
if not exist "inputs\xam.xex" goto missing
if not exist "inputs\hud.xex" goto missing
if not exist "inputs\bootanim.xex" goto missing
set X360_METRO_BOOT=1
set X360_METRO_INTRO=
rem Customize keyboard/controller mappings here; comma separates alternate keys.
set "METRO_INPUT_ARGS=--hid.mnk_mode=true --hid.mnk_mouse=false --hid.mnk_passthrough=false --hid.guide_button=true --hid.keybind_guide=F9 --hid.keybind_dpad_up=W,Up,Shift+Up --hid.keybind_dpad_down=S,Down,Shift+Down --hid.keybind_dpad_left=A,Left,Shift+Left --hid.keybind_dpad_right=D,Right,Shift+Right --hid.keybind_a=Space,Return --hid.keybind_b=Escape,Backspace --hid.keybind_x=X --hid.keybind_y=Y --hid.keybind_left_shoulder=Q --hid.keybind_right_shoulder=E --hid.keybind_left_trigger=1 --hid.keybind_right_trigger=3 --hid.keybind_back=Tab --hid.keybind_start=F10 --hid.keybind_lstick_up=Shift+W --hid.keybind_lstick_down=Shift+S --hid.keybind_lstick_left=Shift+A --hid.keybind_lstick_right=Shift+D --hid.keybind_rstick_up=Ctrl+Up --hid.keybind_rstick_down=Ctrl+Down --hid.keybind_rstick_left=Ctrl+Left --hid.keybind_rstick_right=Ctrl+Right"
set X360_METRO_GUIDE_UI=
set X360_METRO_GUIDE_TRACE=
set X360_METRO_PROFILE_TRACE=
rem Keep the original guest mode independent of the desktop window size.
set "METRO_VIDEO_ARGS=--ui.video_mode_width=1280 --ui.video_mode_height=720"
set "METRO_SCALE_ARGS="
set "METRO_LOG=metro.log"
if /i "%~1"=="hd" (
    set "METRO_SCALE_ARGS=--gpu.resolution_scale_x=2 --gpu.resolution_scale_y=2"
    set "METRO_LOG=metro-hd.log"
)
if /i "%~1"=="1080p" (
    set "METRO_VIDEO_ARGS=--ui.video_mode_width=1920 --ui.video_mode_height=1080"
    set "METRO_LOG=metro-1080p.log"
)
if /i "%~1"=="intro" set X360_METRO_INTRO=1
if /i "%~1"=="guide" goto guide
if /i "%~1"=="profile-preflight" goto profilepreflight
if /i "%~1"=="preflight" goto preflight
goto boot
:guide
set X360_METRO_GUIDE_UI=1
set X360_METRO_GUIDE_TRACE=1
set X360_METRO_PROFILE_TRACE=1
:boot
start "" /wait "%CD%\dash_17559.exe" --title.game_root="%CD%\inputs" --title.entry=dash.xex --gpu.driver=vulkan --ui.fullscreen=false --ui.window_width=1280 --ui.window_height=720 %METRO_VIDEO_ARGS% %METRO_SCALE_ARGS% %METRO_INPUT_ARGS% --log.level=info --log.flush_level=info > "%METRO_LOG%" 2>&1
set "code=%ERRORLEVEL%"
echo Native host exit code: %code%. See %METRO_LOG%.
pause
exit /b %code%
:profilepreflight
set X360_METRO_PROFILE_MODULE_PREFLIGHT=1
goto runpreflight
:preflight
set X360_METRO_PROFILE_MODULE_PREFLIGHT=
:runpreflight
set X360_METRO_BOOT=
set X360_METRO_INTRO=
start "" /wait "%CD%\dash_17559.exe" --title.game_root="%CD%\inputs" --title.entry=dash.xex > local-preflight.log 2>&1
set "code=%ERRORLEVEL%"
type local-preflight.log
echo Preflight exit code: %code%
pause
exit /b %code%
:missing
echo Missing verified original input files. Run Prepare Inputs.cmd first.
pause
exit /b 1
"""
PREPARE=r"""@echo off
setlocal
cd /d "%~dp0"
py -3 --version >nul 2>&1
if errorlevel 1 goto python
py -3 tools\prepare_windows_inputs.py
goto result
:python
python tools\prepare_windows_inputs.py
:result
set "code=%ERRORLEVEL%"
echo Input preparation exit code: %code%
pause
exit /b %code%
"""
README="""# Metro 17559 native Windows x64 diagnostic build

This package contains native AMD64 PE32+ code, not an Xbox 360 emulator or a
video mockup. The current dashboard startup is experimental and may crash.
The CI Windows mapping result is in windows-preflight.json, if present.
A passed mapping preflight is not verification of a working interactive menu.

Requirements: Windows 10/11 x64, current Vulkan-capable GPU drivers, Microsoft
Visual C++ 2015–2022 x64 Redistributable if not installed. Python 3.11+ is only
needed to prepare the local original inputs.

1. Extract the complete artifact into its own folder; keep the DLLs beside
   dash_17559.exe.
2. Run Prepare Inputs.cmd to retrieve the exact locally authorized original
   firmware and fonts from the project's existing configured owner archive.
   Alternatively place your own already verified runtime input tree in inputs/.
   Original XEXs, flash resources, and fonts are not bundled.
3. Run Verify Inputs.cmd for the native mapping-only diagnostic.
4. Run Launch Metro.cmd for the original dashboard. Launch with Intro.cmd also
   runs the original boot animation on the same runtime first, with diagnostic
   timing. Keyboard-to-controller mode is enabled in both launchers.
   WASD/arrows: D-pad; Space/Enter: A; Escape/Backspace: B; Q/E: LB/RB;
   X/Y: X/Y; 1/3: LT/RT; Tab: Back; F10: Start; F9: Guide request.
   Shift+WASD moves the left stick; Ctrl+arrows move the right stick.
   Edit METRO_INPUT_ARGS in launch.cmd to customize bindings. Focus the window.
   Guide display still requires the separate diagnostic and is unverified.
   Launch Metro HD.cmd preserves the 720p guest mode and requests 2x internal
   rendering on both axes (nominally 2560x1440). Launch Metro 1080p Diagnostic.cmd
   instead exposes a 1920x1080 guest mode at the default GPU scale, to distinguish
   guest text/layout behavior from host scaling. Both bypass the intro and write
   separate logs. These are unvalidated graphics diagnostics; normal and intro
   launch retain the original rendering-scale default.
5. If it closes or crashes, retain metro.log and the build commit in
   native-package.json for diagnosis.

Experimental local profile storage (not yet verified to sign in):
stage a copy of your own original CON profile package with
python tools\\stage_metro_profile.py <profile-file> --storage-root user\\metro-17559\\profile-storage
then set X360_METRO_LOCAL_PROFILES=1 before launching. This only exposes the
isolated Content directory to original XAM. It does not authenticate Xbox Live.
If your SDK user root is customized, use that root instead. Keep profile
packages and logs private; never upload them to GitHub or build artifacts.

Direct command from cmd.exe, after preparing inputs:
set X360_METRO_BOOT=1
dash_17559.exe --title.game_root="%CD%\\inputs" --title.entry=dash.xex --gpu.driver=vulkan

No original firmware file is included in the downloadable artifact. The
local setup script checks exact sizes and SHA-256 digests before staging.
"""
def package(folder,output,commit,sdk_source,profile_modules=False):
    files=binary_files(folder,profile_modules)
    if output.exists():raise ValueError("package output must be fresh")
    output.mkdir(parents=True)
    rows=[]
    for src in files:
        info=pe_identity(src)
        dst=output/src.name
        shutil.copy2(src,dst)
        rows.append({"file":dst.name,"bytes":dst.stat().st_size,
                     "sha256":hashlib.sha256(dst.read_bytes()).hexdigest(),**info})
    for rel in SUPPORT:
        dst=output/rel;dst.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(ROOT/rel,dst)
    licenses=output/"licenses"
    licenses.mkdir()
    for name in ("LICENSE","LICENSE.md","LICENSE.txt","NOTICE","NOTICE.md","THIRD_PARTY_NOTICES"):
        for label,root in (("project",ROOT),("rexglue-sdk",sdk_source)):
            if (root/name).is_file():shutil.copy2(root/name,licenses/f"{label}-{name}")
    launchers={"Prepare Inputs.cmd":PREPARE,"launch.cmd":LAUNCH,
                      "Launch Metro.cmd":'@echo off\ncall "%~dp0launch.cmd"\n',
                      "Launch Metro HD.cmd":'@echo off\ncall "%~dp0launch.cmd" hd\n',
                      "Launch Metro 1080p Diagnostic.cmd":'@echo off\ncall "%~dp0launch.cmd" 1080p\n',
                      "Launch with Intro.cmd":'@echo off\ncall "%~dp0launch.cmd" intro\n',
                      "Verify Inputs.cmd":'@echo off\ncall "%~dp0launch.cmd" preflight\n'}
    if profile_modules:
        launchers.update({
            "Launch Guide Diagnostic.cmd":'@echo off\ncall "%~dp0launch.cmd" guide\n',
            "Verify Profile Modules.cmd":'@echo off\ncall "%~dp0launch.cmd" profile-preflight\n'})
    for name,text in launchers.items():
        (output/name).write_bytes(text.replace("\r\n","\n").replace("\n","\r\n").encode("ascii"))
    details=README
    if profile_modules:
        details+="\nThis diagnostic includes all five original native profile UI DLLs.\nVerify Profile Modules.cmd runs ten load/unload cycles without executing\ntheir entrypoints. Launch Guide Diagnostic.cmd enables the original Guide\nstartup hardware experiment and status traces; F9 requests the Guide. Neither launcher signs in\na user or proves that the Guide opens.\n"
    (output/"README.txt").write_text(details,encoding="utf-8")
    (output/"windows-preflight.json").write_text(json.dumps({"passed":False,"status":"not_run","interactive_dashboard_verified":False},indent=2)+"\n")
    report={"commit":commit,"architecture":"Windows AMD64 PE32+","configuration":"Release",
            "original_inputs_included":False,"interactive_dashboard_verified":False,
            "profile_modules_included":profile_modules,"profile_module_dlls":sorted(PROFILE_DLLS) if profile_modules else [],
            "guide_verified":False,"sign_in_verified":False,"binaries":rows}
    (output/"native-package.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"binaries":len(rows),"bytes":sum(r["bytes"] for r in rows),"commit":commit}))
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("folder",type=Path)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--commit",required=True)
    p.add_argument("--sdk-source",type=Path,required=True)
    p.add_argument("--profile-modules",action="store_true")
    a=p.parse_args()
    if not all(x.resolve().is_relative_to(ROOT/"build") for x in (a.folder,a.output,a.sdk_source)):
        p.error("build paths only")
    package(a.folder,a.output,a.commit,a.sdk_source,a.profile_modules)
if __name__=="__main__":main()
