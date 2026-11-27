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
