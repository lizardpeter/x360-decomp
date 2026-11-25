#!/usr/bin/env python3
"""Record generated-file metadata without exporting generated source."""
import argparse
import hashlib
import json
from pathlib import Path

def receipt(directory, status):
    files = []
    if directory.exists():
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise ValueError("unexpected generated symlink")
            if path.is_file():
                data = path.read_bytes()
                files.append({"path": path.relative_to(directory).as_posix(),
                              "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    cpp = [r for r in files if Path(r["path"]).suffix.lower() in (".cpp", ".cc", ".cxx")]
    return {"exit_code": status, "codegen_success": status == 0 and bool(cpp),
            "file_count": len(files), "cpp_files": len(cpp),
            "generated_bytes": sum(r["bytes"] for r in files), "files": files}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory", type=Path)
    p.add_argument("--status", type=int, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    result = receipt(a.directory, a.status)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k:v for k,v in result.items() if k != "files"}))
    if not result["codegen_success"]:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
