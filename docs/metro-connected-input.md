# Connected input regression

The live original XAM callback accepted hosted device 0 as guest port 0 in run 45941015478. The earlier test covered unmapped callbacks and rejection only. This follow-up exercises the actual SDK input system, actual guest-thread export dispatcher, and a controlled test driver with two ports. It checks callback ABI, port assignment, idempotent enumeration, distinct button/axis values, packet counters, capability encoding, invalid context and overlap rejection, and unplugged read failures. The controlled driver exists only in tests; production remains host-provider-backed. Unplug notification/rebinding and full original dashboard navigation remain unverified. This branch adds test infrastructure only and does not cancel a graphical build.

The regression is now included in the main integrated input suite, not a separate patch workflow.
