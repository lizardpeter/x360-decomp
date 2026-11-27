#!/usr/bin/env python3
"""Install the genuine PIRS *public* verification-key lookup used by retail fonts.

The source is the existing, independently authenticated PIRS public modulus.
This service never accepts private keys, console keys, arbitrary trust roots,
modified signatures or a replacement verification result.
"""
import hashlib
import struct
from verify_retail_firmware import KEY

STUB="REX_EXPORT_STUB(__imp__XeKeysGetKey);"
INCLUDE="#include <rex/kernel/title_runtime.h>"
PUBLIC_SIZE=0x110
PUBLIC_ID=0x39

def modulus():
    if len(KEY)!=PUBLIC_SIZE or struct.unpack_from(">IIQ",KEY)!=(32,3,0):
        raise ValueError("unexpected pinned PIRS public key header")
    # The existing PIRS checker consumes qword-little-endian, most significant
    # first. The SDK bignum routine consumes big-endian, least significant first.
    canonical=b"".join(KEY[i:i+8][::-1] for i in range(16,len(KEY),8))
    number=int.from_bytes(canonical,"big")
    if number.bit_length()!=2048 or not number&1:
        raise ValueError("invalid pinned public modulus")
    return number

def guest_number(number):
    if not 0<=number<1<<2048:raise ValueError("outside RSA-2048")
    return b"".join(((number>>(i*64))&((1<<64)-1)).to_bytes(8,"big") for i in range(32))

def guest_public_blob():
    return struct.pack(">IIQ",32,3,0)+guest_number(modulus())

def c_bytes(data):
    return ",\n".join("    "+", ".join(f"0x{b:02X}" for b in data[i:i+16]) for i in range(0,len(data),16))

def c_words(data):
    return ",\n".join("    "+", ".join(f"0x{v:08X}u" for v in struct.unpack(">"+str(len(data[i:i+32])//4)+"I",data[i:i+32])) for i in range(0,len(data),32))

def corrected(source):
    if source.count(STUB)!=1 or source.count(INCLUDE)!=1 or "MetroPirsPublicKey" in source:
        raise ValueError("unexpected public verification provider anchor")
    body=r"""
namespace rex::kernel::xboxkrnl {
namespace {
// Only the independently authenticated Microsoft PIRS public verification key.
// No private or per-console keys, no signing operation, no alternate trust root.
constexpr std::array<u8,0x110> MetroPirsPublicKey{{
@PUBLIC_BYTES@
}};
}
u32 XeKeysGetKey_entry(u32 id, u32 key_address, u32 length_address) {
  if (id!=0x39u) return X_STATUS_NOT_SUPPORTED;
  auto& memory=kernel::GetCurrent().GetGuestMemory();
  if (!length_address || !memory.GetWritableSpan(length_address,sizeof(be_u32)))
    return X_STATUS_ACCESS_VIOLATION;
  const auto length=memory.Load<be_u32>(length_address);
  if (!length) return X_STATUS_ACCESS_VIOLATION;
  // The observed original caller supplies exactly 272 bytes. Do not touch
  // either output on a length mismatch or permit overlapping guest ranges.
  if (static_cast<u32>(*length)!=MetroPirsPublicKey.size())
    return X_STATUS_BUFFER_TOO_SMALL;
  if (!key_address) return X_STATUS_ACCESS_VIOLATION;
  if (u64{key_address}<u64{length_address}+sizeof(be_u32) &&
      u64{length_address}<u64{key_address}+MetroPirsPublicKey.size())
    return X_STATUS_INVALID_PARAMETER;
  auto target=memory.GetWritableSpan(key_address,MetroPirsPublicKey.size());
  if (!target) return X_STATUS_ACCESS_VIOLATION;
  std::memcpy(target->data(),MetroPirsPublicKey.data(),MetroPirsPublicKey.size());
  // Input length already exactly equals the output length. This does not
  // assert that any resource signature is valid; retail must verify it.
  return X_STATUS_SUCCESS;
}
}
REX_EXPORT(__imp__XeKeysGetKey,rex::kernel::xboxkrnl::XeKeysGetKey_entry)
""".replace("@PUBLIC_BYTES@",c_bytes(guest_public_blob()))
    return source.replace(INCLUDE,INCLUDE+"\n#include <rex/kernel/guest_memory.h>",1).replace(STUB,body,1)

def vector():
    n=modulus()
    # Deterministic, nontrivial public RSA vector (not a signature or private
    # operation). Python big integers give independent expected arithmetic.
    data=b"".join(hashlib.sha256(b"metro-public-rsa-vector"+bytes([i])).digest() for i in range(8))
    x=int.from_bytes(data,"big")%n
    return guest_number(x),guest_number(pow(x,3,n))

def native_test():
    raw,expected=vector()
    return r"""
REX_TEST_CASE("metro_io_runtime: genuine PIRS public verification and strict guest key contract",
              "[kernel][crypt][metro_io_runtime]") {
  KernelFixture fixture;
  fixture.RunOnGuestThread([](Caller& c) {
    using namespace rex::kernel;
    const u32 key=c.Alloc(0x118),length=c.Alloc(4);
    for (u32 i=0;i<0x118;i+=4)c.Store32(key+i,0xA5A5A5A5u);
    for (u32 size:{0u,271u,273u}) {
      c.Store32(length,size);
      CHECK(c.Kernel("XeKeysGetKey",{0x39,key,length})==X_STATUS_BUFFER_TOO_SMALL);
      CHECK(c.Load32(length)==size);
      CHECK(c.Load32(key)==0xA5A5A5A5u);
    }
    c.Store32(length,0x110);
    CHECK(c.Kernel("XeKeysGetKey",{0xFFFF,key,length})==X_STATUS_NOT_SUPPORTED);
    CHECK(c.Kernel("XeKeysGetKey",{0x39,0,length})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("XeKeysGetKey",{0x39,key,0xfffffffc})==X_STATUS_ACCESS_VIOLATION);
    CHECK(c.Kernel("XeKeysGetKey",{0x39,length,length})==X_STATUS_INVALID_PARAMETER);
    CHECK(c.Load32(key)==0xA5A5A5A5u);
    REQUIRE(c.Kernel("XeKeysGetKey",{0x39,key,length})==0);
    CHECK(c.Load32(length)==0x110);
    CHECK(c.Load32(key)==32);
    CHECK(c.Load32(key+4)==3);
    CHECK(c.Load32(key+8)==0);
    CHECK(c.Load32(key+12)==0);
    CHECK(c.Load32(key+0x110)==0xA5A5A5A5u);
    CHECK(c.Load32(key+0x114)==0xA5A5A5A5u);
    constexpr u32 input_words[]={
@INPUT@
    };
    constexpr u32 expected_words[]={
@EXPECTED@
    };
    const u32 in=c.Alloc(256),out=c.Alloc(256),hash=c.Alloc(20),salt=c.Alloc(12);
    for (u32 i=0;i<64;++i) {
      c.Store32(in+i*4,input_words[i]);
      c.Store32(out+i*4,0xA5A5A5A5u);
    }
    REQUIRE(c.Kernel("XeCryptBnQwNeRsaPubCrypt",{in,out,key})==1);
    for (u32 i=0;i<64;++i)CHECK(c.Load32(out+i*4)==expected_words[i]);
    // A present public key is not permission to accept an invalid signature.
    for (u32 i=0;i<256;i+=4)c.Store32(in+i,0);
    for (u32 i=0;i<20;i+=4)c.Store32(hash+i,0);
    for (u32 i=0;i<12;i+=4)c.Store32(salt+i,0);
    CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{in,hash,salt,key})==0);
  });
}
""".replace("@INPUT@",c_words(raw)).replace("@EXPECTED@",c_words(expected))
