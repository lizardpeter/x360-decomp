# Native Metro profile UI integration gates

The original dashboard, XAM and HUD use the 17559 resource tree. The new
profile UI staging is an isolated compile and registration trial, not a
replacement account implementation. It cannot mark a user signed in.

| Module | Original guest base | Loaded image bytes | PDATA entries | XAM imports |
|---|---:|---:|---:|---:|
| signin | 0x90100000 | 274432 | 456 | 232 |
| deviceselector | 0x916D0000 | 94208 | 129 | 87 |
| vk | 0x917D0000 | 114688 | 177 | 89 |
| gamerprofile | 0x90100000 | 319488 | 715 | 189 |
| createprofile | 0x90100000 | 114688 | 222 | 113 |

These totals (1,699 original PDATA functions; 710 bindings across 366 XAM
ordinals) are independently checked against original decoded metadata and then
against original PIRS bytes at staging time. They do not count native function
registrations or a completed sign-in.

The signin, gamerprofile and createprofile images occupy overlapping address
ranges. They cannot be simultaneously registered. The isolated native trials
require each original module entry and XAM import thunk to have a real host
function in its registration table. The SDK regression separately exercises
the real memory/dispatcher with synthetic callbacks at the original image
and text ranges, checking overlap refusal and repeated unregister/reload.

Before adding these modules to the working dashboard's live loader:

1. Require the native registration receipt for each module. Investigate
   missing entries, unresolved functions, and codegen errors rather than
   generating a stub to make a count pass.
2. Compare all exact required original XAM target addresses against the
   generated XAM mapping table. The integrated build writes this coverage in
   zero-address-mappings.json. PDATA membership alone is not sufficient.
3. Extend the native registry only for the verified original module paths;
   preserve original import slot/thunk ABI and require every XAM export
   target. Never route to a hosted XAM placeholder.
4. Test module lifetime, attach/detach, overlapping image release and
   dependency reference ownership on the live guest. The synthetic regression
   does not establish that the original profile UI transitions are safe.
5. Use original profile enumerators, storage-device state, account metadata
   and original sign-in state transitions. No online authentication,
   fabricated XUIDs, forced sign-in flags, or private keys.

The public font verification provider is separate from account handling. It
supplies only the genuine PIRS RSA public verification key requested by the
original signed-font reader. The guest's signature result is not modified.

## Opt-in integrated native build

The Linux dashboard workflow now exposes a `profile_modules` manual-run input.
The default build retains the established dashboard/bootanim baseline. The
opt-in path uses the same native dashboard host with five additional generated
DLLs, original flash resources, exact base/size/entry codegen checks, and
retail XAM dependency binding. It requires every original XAM target and
all five entrypoint/import thunk tables to be present before native linking.
The runtime refuses a profile UI load if its native shared library is not
registered, rather than attaching an uncompiled XEX. Alias paths normalize to
the read-only flash tree. No actual sign-in is asserted until a live test.

The dedicated integrated workflow calls the production Linux build with
`profile_modules: true`. Its additional load-only gate alternates each original
module's bare and flash alias across two cycles, verifies every original import
slot and native thunk, and checks 1,420 XAM bindings in ten real loader cycles.
It does not execute DllMain, alter the user's profile, or claim actual sign-in.
The ordinary build remains independent of this opt-in gate.

The isolated native module registration gate passed on run 46024434000.
The expanded original storage audit (46026155953) recovered 20 import
ordinals and 1,394 bounded leaf/tail wrappers. No direct path from the 41
local profile exports reaches a storage import: the original APIs cross
an indirect app-message/object dispatch boundary. The new integrated-only
Guide/cancel test uses the SDK's actual Guide button setting and the normal
guest pad bridge. It does not invoke sign-in or create an account. Status-only
trace markers identify local API entry, original UI module entry and storage
return categories without logging original account bytes or identities.
Screenshots and original frame progress are independent evidence; no visual
verification or sign-in result is claimed by the input test itself.
