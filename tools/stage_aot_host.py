#!/usr/bin/env python3
"""Create a reproducible SDK-hosted AOT build in an ignored trial directory."""
import argparse
import json
from pathlib import Path
from prepare_recompilation import ROOT, EXPECTED, original, prepare
from pirs import parse as parse_pirs

def write_exact(path, text):
    if path.exists() and path.read_text() != text:
        raise ValueError(f"existing scaffold differs: {path.name}")
    path.write_text(text)

def stage(module, output):
    payload = original("dash") if module == "dash_17559" else parse_pirs(original("pirs"))["$flash_xam.xex"]["payload"]
    result = prepare(output, module, payload)
    folder = output / module
    # SDK package supplies the compiler/runtime glue; this host is a trial,
    # not a replacement for our independent authored runtime.
    write_exact(folder / "CMakeLists.txt", f"""cmake_minimum_required(VERSION 3.25)
project({module} LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(rexglue 0.11.0 REQUIRED CONFIG)
rexglue_project({module})
add_executable({module} src/main.cpp)
rexglue_setup_target({module})
""")
    (folder / "src").mkdir(exist_ok=True)
    write_exact(folder / "src/main.cpp", f"""#include <rex/app/title_app.h>
#include "generated/{module}_init.h"
class MetroDiagnosticApp final : public rex::app::TitleApp {{
public:
    MetroDiagnosticApp() : TitleApp("{module}", kPPCImageConfig) {{}}
}};
REX_TITLE_APP(MetroDiagnosticApp)
""")
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--module", choices=tuple(EXPECTED), required=True)
    p.add_argument("--output", type=Path, default=ROOT/"build/aot-host")
    a=p.parse_args()
    output=a.output.resolve()
    if not output.is_relative_to((ROOT/"build").resolve()):
        p.error("host trial must stay under ignored build/")
    print(json.dumps(stage(a.module,output),sort_keys=True))

if __name__ == "__main__":
    main()
