# Metro writable dashboard cache isolation

Run 45942627248 shows the original dashboard startup attempting to open the physical hard-disk Partition1 Cache directory and getting access denied. The generic SDK aliases that partition to the read-only title input tree. Making the game root writable would risk changing hash-verified firmware and is not acceptable.

The dedicated diagnostic Metro boot now mounts a real writable host directory under the configured user-data root, metro-17559/hdd-cache, and redirects only the original physical Cache path via the existing SDK symbolic-link resolver. The original firmware and game root remain read-only. Both the physical and game: aliases must resolve before boot. The cache and original input paths must not overlap after canonicalization. This does not claim to implement the full Xbox 360 disk partition or physical hardware; root partition paths and name.txt are unchanged. No existing cache contents are erased.

The native guest-thread test writes through the physical path, reopens through game:, and verifies storage is isolated from the firmware tree. Boot and regression verification are pending.
