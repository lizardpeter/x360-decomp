# Native offline profile integration

## Objective

Use actual user-owned Xbox 360 profile packages and original XAM sign-in,
not a hard-coded signed-in flag, synthetic online identity or a replacement UI.
Local sign-in is distinct from Xbox Live authentication. No token, secret,
console key, credentials, or private profile data belongs in CI or Git.

The pinned SDK `UserProfile` is a single placeholder ("User", constant XUID,
state 1), while the 521 original dashboard XAM exports route to the recompiled
retail XAM. Changing the SDK placeholder cannot establish real retail sign-in.
The next step is to recover original storage enumeration, profile parsing,
selection and notification paths. Do not substitute the SDK's XamUser APIs.

## Local staging

`python tools/stage_metro_profile.py <original E-prefixed profile file> --storage-root <isolated profile-storage directory>`

The input is a user-owned CON STFS package. The tool checks header type,
metadata version, profile content category, dashboard title, original file
name and bounded size, then makes a byte-identical copy under
`Content/<profile-id>/FFFE07D1/00010000/<profile-id>`.
It does not change the source, sign or decrypt the package, verify its
cryptographic signature, or establish sign-in. A staged profile is private
local data and is never to be uploaded as a build artifact.
Original profile ID is not an authenticated Xbox Live XUID.

## Native renderer migration

Retain current ReXGlue Xenos backend as the reference through complete
dashboard bring-up. Inventory original high-level D3D/XUI draw calls,
texture/buffer formats, shader variants, render targets and synchronization.
Implement a separate native Vulkan renderer at the recovered API boundary,
not a second PM4 interpreter. Use native resource lifetimes, offline SPIR-V
shader conversion, explicit synchronization, and compare frame captures
and UI input behavior against verified reference sessions. Require no
Xenos register, EDRAM, or PM4 emulation in the eventual native path.
Do not replace original XUI application logic. No minimum Vulkan revision
is imposed until feature requirements and hardware support are established.

## Validation gates

1. Import an authorized profile locally without modifying its source.
2. Original XAM enumerates it using its actual storage API.
3. Original profile selection and sign-in state transition to local signed-in.
4. Gamertag, profile picture, achievements and settings reflect actual data.
5. Original sign-out and reload work; offline state never claims Live access.
6. Native rendering preserves these behaviors without changing user state.

At this stage only staging is implemented; original enumeration and sign-in
remain unverified. Test fixtures use synthetic package headers, not real accounts.

The experimental mount is now opt-in via `X360_METRO_LOCAL_PROFILES=1`. It maps the staged `Content` directory at `\\Device\\Harddisk0\\Partition1\\Content` before original XAM attach. The usual SDK user-root default is the application root's `user` directory. It does not model a physical partition/device enumeration or establish signed-in state; actual guest discovery is still required. The launch package includes the staging tool. No profile input is staged by CI.

### Explicit Content alias and directory handles

The pinned SDK originally checked the underlying firmware provider for an absolute linked mount root and resolved directory-relative paths entirely inside the original provider. Both behaviors are corrected by the hosted I/O patch: cross-provider roots retain their own ownership and write policy; directory-relative opens follow an explicit link only when the canonical path stays inside the opened directory and resolves to another provider. The synthetic regression exercises absolute and relative opens, nested reads and writes, component boundaries and read-only firmware. It does not merge directory listings across mounts or implement physical storage notifications. Native compilation, actual original XAM enumeration and local sign-in remain separate validation gates.

### Original profile UI module census

The first evidence run (46020054414) found 139 dashboard roots, 179 direct profile API calls and a capped union of 1,000 nodes; original XAM had 20 PDATA-aligned roots and 65 nodes. The expanded analyzer separately verifies and traces the original `gamerprofile.xex` and `createprofile.xex` images. Their verified decoded metadata contains 715 and 222 PDATA functions respectively; they share an image base, so their addresses are not globally unique and do not imply simultaneous loading. Internal sign-in UI, device enumeration and notification APIs now have separate bounded graphs and XAM target joins. These are static direct-call observations, not proofs of runtime profile selection or module loading. No user package is consumed.

### Guest enumeration I/O correction

The expanded evidence job 46020806807 passed: 282 dashboard, 40 gamerprofile and 21 createprofile direct local API calls joined to original XAM exports. All 85 per-API graphs across four images remained below their individual node caps. The union dashboard graph is still capped at 1,000. A new kernel patch validates counted names and output spans for directory and full-attribute queries, reports exact directory record bytes, retains an overflowing entry for retry, rejects non-directory handles, and bounds volume information writes. Synthetic guest-thread tests exercise overflow/retry, restart, exact byte counts and invalid/overlapping pointers. The STFS device creation/control and physical notification contracts remain unresolved; no fake account state or physical device is provided.

### Native module compile proof and deeper storage graph

The isolated module run 46024434000 completed successfully: signin 1,074 native mappings, deviceselector 289, vk 357, gamerprofile 1,122, createprofile 441, with all 710 required XAM import thunks registered. The sum is 3,283 native mappings, including import thunks and discovered functions; these are not 3,283 independently recovered source functions. The first integrated build exposed a compiler indentation diagnostic in the generated registry, corrected on main. The native kernel regression at 46023340356 passed 1,526 assertions, including the genuine public font key RSA vector and profile overlay range tests.

A new original-image storage graph follows direct calls and conservatively bounded leaf/tail wrappers beyond PDATA. It checks 20 exact original kernel storage import ordinals, identifies their caller sites and return-use operands, and finds bounded shortest direct paths from the original local XAM API roots. Indirect calls and unresolved destinations are counted rather than guessed. This is evidence for reconstructing the real STFS/device lifecycle, not a replacement storage provider or claim of sign-in. No profile bytes enter this workflow.
