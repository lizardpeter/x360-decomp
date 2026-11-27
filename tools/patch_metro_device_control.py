#!/usr/bin/env python3
"""Handle a physical ATA pass-through request on a hosted file, without faking a drive."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

OLD = '''  } else {
    REX_KERNEL_STUB("NtDeviceIoControlFile(0x{:X})", static_cast<u32>(io_control_code));
    REX_ASSERT_ALWAYS();
    return X_STATUS_INVALID_PARAMETER;
  }'''

NEW = '''  } else if (io_control_code == 0x4D028) {
    // IDE pass-through is not available on the hosted filesystem. Never
    // forward guest ATA commands to a physical host drive or claim success.
    // This is an immediate error, not a queued completion: leave the
    // output buffer, IO status block and event untouched.
    const auto opened_file = kernel::GetCurrent().GetObjectTable().Get<FileObject>(handle);
    if (!opened_file) return X_STATUS_INVALID_HANDLE;
    REXKRNL_WARN("Hosted IDE pass-through unsupported: path={} input_bytes={} output_bytes={}",
                 opened_file->GetAbsolutePath(), input_buffer_len, output_buffer_len);
    return X_STATUS_NOT_SUPPORTED;
  }''' + OLD

def corrected(source):
    if NEW in source or source.count(OLD) != 1:
        raise ValueError("unexpected or previously patched device-control dispatch")
    return source.replace(OLD, NEW, 1)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk", type=Path)
    a = p.parse_args()
    if subprocess.check_output(["git", "-C", str(a.sdk), "rev-parse", "HEAD"], text=True).strip() != REVISION:
        raise ValueError("unexpected SDK revision")
    path = a.sdk/"src/kernel/xboxkrnl/xboxkrnl_io.cpp"
    path.write_text(corrected(path.read_text()))
    subprocess.run(["git", "-C", str(a.sdk), "diff", "--check"], check=True)

if __name__ == "__main__":
    main()
