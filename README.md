# Xbox 360 decompilation

Evidence-based reconstruction of the retail Xbox 360 Metro V2 dashboard, build **2.0.17559.0**. The original dashboard, XAM, Guide, resources, and console-facing services are the initial targets. The long-term goal is a native host executable, with a separate enhanced build.

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

The initial tooling validates source archives, parses XEX2 import and embedded resource tables, and inventories the original retail PIRS update. It does not yet decode PowerPC machine code, provide native dashboard execution, or reconstruct the Xbox kernel.
