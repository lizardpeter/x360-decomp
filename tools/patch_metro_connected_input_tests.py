#!/usr/bin/env python3
"""Connect the SDK's real input system to the tool-mode guest test fixture."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

def edit(s,old,new,count=1):
    if s.count(old)!=count:raise ValueError("unexpected fixture anchor: "+old)
    return s.replace(old,new)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    p.add_argument("--tests",type=Path,required=True)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    h=a.sdk/"tests/unit/kernel/kernel_fixture.h"
    c=a.sdk/"tests/unit/kernel/kernel_fixture.cpp"
    t=a.sdk/"tests/unit/kernel/xam_input_test.cpp"
    hs=edit(h.read_text(),"class IModule;","class IModule;\nnamespace hid { class IInputSystem; }")
    hs=edit(hs,"std::string ui_driver = {});","std::string ui_driver = {}, std::string input_driver = {});")
    hs=edit(hs,"  rex::apu::IAudioSystem& GetAudio();","  rex::apu::IAudioSystem& GetAudio();\n  rex::hid::IInputSystem& GetInput();")
    cs=edit(c.read_text(),'#include "kernel_fixture.h"','#include "kernel_fixture.h"\n#include <rex/hid/input_system.h>')
    cs=edit(cs,"std::string audio_driver, std::string ui_driver)","std::string audio_driver, std::string ui_driver, std::string input_driver)",2)
    cs=edit(cs,"ui_driver_(std::move(ui_driver)) {}","ui_driver_(std::move(ui_driver)), input_driver_(std::move(input_driver)) {}")
    cs=edit(cs,"    return Ok();\n  }\n\n private:\n  std::vector<IModule*> providers_;","    if (!input_driver_.empty()) {\n      REX_TRY_VOID(GetInput().GetSettings().drivers.SetText(SettingLayer::kTitle, input_driver_));\n    }\n    return Ok();\n  }\n\n private:\n  std::vector<IModule*> providers_;")
    cs=edit(cs,"  std::string ui_driver_;","  std::string ui_driver_;\n  std::string input_driver_;")
    cs=edit(cs,"std::move(ui_driver)),\n        tool","std::move(ui_driver), std::move(input_driver)),\n        tool")
    cs=edit(cs,"                             std::string ui_driver)\n    : impl_","                             std::string ui_driver, std::string input_driver)\n    : impl_")
    cs=edit(cs,"std::move(ui_driver))) {","std::move(ui_driver), std::move(input_driver))) {")
    cs=edit(cs,"rex::ui::IUISystem& KernelFixture::GetUI()","rex::hid::IInputSystem& KernelFixture::GetInput() {\n  return impl_->app.GetInput();\n}\n\nrex::ui::IUISystem& KernelFixture::GetUI()")
    ts=t.read_text()
    if "metro_connected_input:" in ts:raise ValueError("tests already staged")
    for path,content in ((h,hs),(c,cs),(t,ts+"\n"+a.tests.read_text())):path.write_text(content)
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
if __name__=="__main__":main()
