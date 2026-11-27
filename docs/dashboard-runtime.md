# Local dashboard launch resource tree

The staging tool verifies the pinned PIRS and shared resource sources and checks the entire 31-member census before writing the explicit 14-file base runtime tree (dashboard, boot animation, ten selected system modules, one original font resource and shared XUI archive). This is an input layout for a hosted diagnostic session, not a claim of the original flash filesystem layout or a bootable dashboard. It checks the dashboard/XAM hashes against the AOT inputs, never overwrites different files, rejects unsafe destinations, and produces a digest-only receipt. Optional full font complements must be supplied locally and match the exact size/hash pins in target.toml; missing complements are explicitly reported. No patch files are treated as full resources, no encrypted manufacturing module or updater is launched, and no original files or fonts are committed or published. The native validation workflow exercises the base staging tree from verified inputs; it does not execute the guest.

For a local build, after acquiring the pinned pirs and shared_resources objects:

```sh
python tools/stage_dashboard_runtime.py --font-dir /path/to/your/local/originals --require-fonts
```

The default destination is the ignored AOT dashboard input directory. The SDK and our eventual hosted loader must still mount and register the system modules, configure the original UI services and render the dashboard. A receipt records guest_boot_verified=false.

## First live background, not a usable menu

Run 45949049905 initialized the original system object at 401E0900 and presented 241 frames. Both D-pad transitions were consumed by original XAM. Visual inspection of the actual captures shows only the gray gradient; candidates 02–04 and all navigation captures have identical pixels. The run also observed 22 missing XenonJKLatin opens, missing DASHUSER theme paths, a missing hud.xex lookup, and 298336 missing HdDvdRom mount lookups. No menu or navigation is claimed. The user-owned R2 inventory contains candidate original font complements with the exact pinned lengths; the new boot staging checks the already-pinned SHA-256 for each before use, and fails closed if either differs. The new writable DASHUSER area contains no synthetic theme or effect files. Input verification now samples more frequently, waits for actual frame progress, and separately rejects unchanged navigation pixels. HD-DVD polling and the dynamically loaded HUD remain unresolved; do not present the device as connected or substitute a non-original UI.
