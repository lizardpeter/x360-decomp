
#include <rex/xam/input.h>
#include <atomic>

REX_TEST_CASE("metro_connected_input: guest callback binding, packet transitions and isolated ports",
              "[kernel][input][metro_connected_input]") {
  using namespace rex::test_input;
  g_fake = {};
  g_fake[0].devices = {MakePad(1, 0), MakePad(2, 1)};
  g_fake[0].states[1] = Buttons(rex::hid::kPadDPadRight);
  g_fake[0].states[2] = Buttons(rex::hid::kPadB);
  g_fake[0].states[1].left_trigger = 231;
  g_fake[0].states[1].thumb_lx = -2345;
  FakeProvider provider;
  rex::test::KernelFixture fixture({}, {&provider}, {}, {}, "fake_a");
  fixture.RunOnGuestThread([&](rex::test::Caller& c) {
    auto& state = StateOf(c.GetRuntime());
    state.hosted_pad_input = &fixture.GetInput();
    auto& memory = c.GetRuntime().GetGuestMemory();
    static std::atomic<unsigned> callbacks{0};
    callbacks.store(0);
    const u32 callback = state.GetFunctionDispatcher()->AllocateThunk(
      +[](PPCContext& ctx, u8* base) {
        // Test callback only. Mirror the retail callback ABI, not its implementation.
        const u32 context = ctx.r4.u32;
        if (ctx.r3.u32 != context || context < 0x10000001 ||
            context > 0x10000004 || ctx.r5.u32 != 0 || ctx.r6.u32 != 0 ||
            !ctx.r7.u32) {
          ctx.r3.u64 = 0xc000000d;
          return;
        }
        base[ctx.r7.u32] = static_cast<u8>(context - 0x10000001);
        ++callbacks;
        ctx.r3.u64 = 0;
      }, 0);
    REQUIRE(callback != 0);
    c.Kernel("DrvSetUserBindingCallback", {callback});
    REQUIRE(c.GetRuntime().AnnounceHostedPads() == 2);
    CHECK(callbacks.load() == 2);
    CHECK(state.hosted_pad_port[0].load() == 0);
    CHECK(state.hosted_pad_port[1].load() == 1);
    CHECK(c.GetRuntime().AnnounceHostedPads() == 2);
    CHECK(callbacks.load() == 2);
    const u32 data = c.Alloc(24), packet = c.Alloc(4), extra = c.Alloc(4);
    auto read = [&](u32 context) {
      return c.Kernel("XInputdReadState", {context, packet, data, extra});
    };
    REQUIRE(read(0x10000001) == 0);
    const auto first = memory.Load<rex::xam::X_INPUT_GAMEPAD>(data);
    REQUIRE(first);
    CHECK(first->buttons == rex::hid::kPadDPadRight);
    CHECK(first->left_trigger == 231);
    CHECK(first->thumb_lx == -2345);
    CHECK(c.Load32(extra) == 0);
    const auto packet0 = c.Load32(packet);
    REQUIRE(read(0x10000001) == 0);
    CHECK(c.Load32(packet) == packet0);
    g_fake[0].states[1] = Buttons(rex::hid::kPadDPadLeft);
    REQUIRE(read(0x10000001) == 0);
    CHECK(c.Load32(packet) == packet0 + 1);
    CHECK(c.Load8(data) == 0);
    CHECK(c.Load8(data+1) == rex::hid::kPadDPadLeft);
    REQUIRE(read(0x10000002) == 0);
    CHECK(c.Load8(data) == 0x20);
    CHECK(c.Load8(data+1) == 0);
    REQUIRE(c.Kernel("XInputdGetCapabilities", {0x10000002, data, extra}) == 0);
    const auto caps = memory.Load<rex::xam::X_INPUT_CAPABILITIES>(data);
    REQUIRE(caps);
    CHECK(caps->type == 1);
    CHECK(caps->sub_type == 1);
    CHECK(caps->gamepad.buttons == 0xfbff);
    c.Store32(data, 0xdeadbeef);
    c.Store32(packet, 0x11223344);
    c.Store32(extra, 0x55667788);
    CHECK(c.Kernel("XInputdReadState", {0x10000001, packet, data, data+4}) == 0xc0000005);
    CHECK(c.Load32(data) == 0xdeadbeef);
    CHECK(c.Load32(packet) == 0x11223344);
    CHECK(c.Load32(extra) == 0x55667788);
    CHECK(read(0x10000003) == 0xc000009d);
    CHECK(c.Load32(data) == 0xdeadbeef);
    g_fake[0].devices.pop_back();
    g_fake[0].states.erase(2);
    ++g_fake[0].revision;
    CHECK(read(0x10000002) == 0xc000009d);
    CHECK(c.Load32(data) == 0xdeadbeef);
    REQUIRE(read(0x10000001) == 0);
    CHECK(c.Load8(data+1) == rex::hid::kPadDPadLeft);
    state.ResetHostedPadBindings();
  });
  g_fake = {};
}
