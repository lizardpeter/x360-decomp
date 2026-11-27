# Original Guide activation evidence

Integrated run 46028436241: the hosted pad emitted 0x0400 and returned to zero, but none of the captured Guide frames differed from the baseline. No original profile UI entry was observed. The input bridge's successful read alone is not proof of Guide activation.

The original XAM imports DrvSetSysReqCallback at 0x81A72FF4 (ordinal 0x020C). The existing direct-call census identifies four original callers: 816F0368, 816F0410, 816F0AE0 and 816F0DF0. XamInputSendXenonButtonPress (816F2E60), XamShowGuideUI (816C3580) and XamIsGuideDisabled (816E16F0) are independently joined to the original export table. The audit reconstructs the actual registration arguments and bounded candidate callback bodies, reads the input and HUD call sites, and supplies precise original trace points. No private account data or executable payload is emitted. Do not assume a callback ABI or forge a Guide launch.
