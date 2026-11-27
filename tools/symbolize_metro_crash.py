#!/usr/bin/env python3
"""Resolve module-relative crash offsets against the same CI executable and DSOs."""
import re
import subprocess
import sys
from pathlib import Path

def main():
    log, *roots = map(Path, sys.argv[1:])
    seen = set()
    for line in log.read_text(errors="replace").splitlines():
        for name, address in re.findall(r"\(([A-Za-z0-9_.-]+)\+0x([0-9a-fA-F]+)\)", line):
            if (name, address) in seen:
                continue
            seen.add((name, address))
            if not (name.startswith(("librex", "libdash")) or name == "dash_17559"):
                continue
            candidates = []
            for root in roots:
                direct = root/name
                candidates.extend([direct] if direct.is_file() else sorted(root.rglob(name)))
            if not candidates:
                print(f"{name}+0x{address}: not found in native tree or pinned SDK")
                continue
            result = subprocess.run(["addr2line", "-C", "-f", "-e", str(candidates[0]), "0x"+address],
                                    capture_output=True, text=True)
            print(f"{name}+0x{address}: {result.stdout.strip().replace(chr(10), ' | ')}")
if __name__ == "__main__":
    main()
