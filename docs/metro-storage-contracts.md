# Metro hosted storage boundary

Run 45941380448 confirms original XAM attach, original dashboard entry and dynamic module identity. It crashes on a guest-zero read before any frame. Its earlier storage worker reports IoDismountVolumeByName, while the main thread reports failed opens of Harddisk0 name.txt and Cache. The original kernel's mount/volume lifecycle is not yet reconstructed.

The pinned SDK was returning unconditional success for both dismount exports without changing volume state. This branch replaces that false success with validated file-handle and counted-name contracts and an explicit unsupported result for mounted hosted volumes. Missing volumes return the filesystem error. It never unmounts a live host resource tree. This is an honest unsupported hosted operation, not the retail dismount implementation. Guest recovery and relationship to the null read remain unverified.

The same file boundary previously asserted on a missing output handle and dereferenced unchecked nested guest pointers. NtCreateFile and NtOpenFile now validate the output handle, optional status block, object attributes, ANSI string descriptor and counted buffer, including overlap and invalid range checks, before filesystem mutation. The existing path normalization and provider selection remain. Guest-thread regression coverage checks invalid output and input pointers, malformed name lengths, overlapping outputs, handle type errors, and that a failed dismount leaves an existing file readable.

Native regression and boot CI are required. No menu verification is claimed. This branch builds on the console-config branch without changing its running jobs.
