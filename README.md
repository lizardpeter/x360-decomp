# Xbox 360 decompilation

Evidence-based reconstruction of the Xbox 360 operating system. Retail Metro V2 **2.0.17559.0** is the first hosted profile. The long-term goal includes an independently reconstructed boot, hypervisor, kernel, drivers, XAM and system applications, with native host targets and optional enhancements. See [OS architecture](docs/architecture.md), [profiles](profiles/) and [static recompilation](docs/static-recompilation.md).

The repository follows Ghosts, Black Ops II and Black Ops III: generated analysis, authored faithful functions, independent enhancements, and per-function verification. No original executable is claimed reconstructed merely because its headers were parsed.

- [Working rules](AGENTS.md) · [Status](STATUS.md) · [Roadmap](docs/roadmap.md)
- [Original input contract](docs/originals.md) · [Verification](docs/verification.md)
- [Pinned sources](target.toml)

## First analysis

Python 3.11+; no third-party Python dependencies.

```sh
python tools/fetch_originals.py
python tools/analyze.py
python tools/status.py
python -m unittest discover -s tests -v
```

For an existing exact-source handoff ZIP, use `python tools/fetch_originals.py --artifact /path/to/handoff.zip`. All seven required objects must match size and SHA-256. Original files are retained in ignored `originals/`. No binaries or fonts are committed.

The initial tooling verifies and decodes unencrypted XEX images, inventories functions and imports, and runs Ghidra analysis. Native dashboard execution, authored function parity and full-system boot are not established.
