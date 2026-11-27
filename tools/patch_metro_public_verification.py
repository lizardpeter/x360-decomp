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
NAMESPACE="namespace rex::kernel::xboxkrnl {"
CLOSE="}  // namespace rex::kernel::xboxkrnl"
EXPORT="REX_EXPORT(__imp__XeKeysGetKey, rex::kernel::xboxkrnl::XeKeysGetKey_entry)"
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
    if source.count(NAMESPACE)!=1 or source.count(CLOSE)!=1 or not source.index(NAMESPACE)<source.index(STUB)<source.index(CLOSE):
        raise ValueError("unexpected crypto export namespace")
    body=r"""
namespace {
// Only the independently authenticated Microsoft PIRS public verification key.
// No private or per-console keys, no signing operation, no alternate trust root.
constexpr std::array<u8,0x110> MetroPirsPublicKey{{
@PUBLIC_BYTES@
}};
}
u32 XeKeysGetKey_entry(u32 id, u32 key_address, u32 length_address) {
  if (id!=0x39u) return X_STATUS_NOT_SUPPORTED;
  auto& memory=::rex::kernel::GetCurrent().GetGuestMemory();
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
""".replace("@PUBLIC_BYTES@",c_bytes(guest_public_blob()))
    return (source.replace(INCLUDE,INCLUDE+"\n#include <rex/kernel/guest_memory.h>",1)
            .replace(STUB,body,1).replace(CLOSE,CLOSE+"\n\n"+EXPORT,1))

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

# Independently generated synthetic public known-answer vectors, with private
# keys discarded. No Microsoft signature is created or modified here.
SIG_VERIFY_OLD=r"""u32 XeCryptBnQwBeSigVerify_entry(MappedVoid sig, MappedVoid hash, MappedVoid salt,
                                 GuestPtrT<XECRYPT_RSA> rsa) {
  const u32 exponent = rsa->public_exponent;
  if (rsa->size != kSigDigits || (exponent != 3 && exponent != 0x10001)) {
    return 0;
  }
  EXCRYPT_SIG recovered;
  if (!XeCryptBnQwNeRsaPubCrypt_entry(MappedU64::FromHost(sig.As<be_u64*>()),
                                      MappedU64::FromHost(reinterpret_cast<be_u64*>(&recovered)),
                                      rsa)) {
    return 0;
  }
  EXCRYPT_SIG expected;
  ExCryptBnQwBeSigFormat(&expected, hash.As<const u8*>(), salt.As<const u8*>());
  return std::memcmp(&recovered, &expected, sizeof(expected)) == 0 ? 1 : 0;
}"""
SIG_VERIFY_NEW=r"""u32 XeCryptBnQwBeSigVerify_entry(u32 sig_address, u32 hash_address, u32 salt_address,
                                 u32 key_address) {
  // This Xbox signature format is not ordinary RSA or PKCS1. The public
  // signature is already in the Montgomery representation expected by
  // the original repeated-square/multiply verification procedure.
  auto& memory=::rex::kernel::GetCurrent().GetGuestMemory();
  if (!sig_address || !hash_address || !salt_address || !key_address) return 0;
  const auto sig=memory.GetReadOnlySpan(sig_address,256);
  const auto hash=memory.GetReadOnlySpan(hash_address,20);
  const auto salt=memory.GetReadOnlySpan(salt_address,10);
  const auto key=memory.GetReadOnlySpan(key_address,272);
  if (!sig || !hash || !salt || !key) return 0;
  XECRYPT_RSA header{};
  std::memcpy(&header,key->data(),sizeof(header));
  const u32 exponent=header.public_exponent;
  if (header.size!=kSigDigits || (exponent!=3 && exponent!=0x10001)) return 0;
  std::array<be_u64,kSigDigits> key_words{},sig_words{},recovered{};
  std::memcpy(key_words.data(),key->data()+sizeof(header),256);
  std::memcpy(sig_words.data(),sig->data(),256);
  const Number modulus=LoadNumber(key_words.data(),kSigDigits);
  const Number input=LoadNumber(sig_words.data(),kSigDigits);
  if (!(modulus[0]&1) || !(modulus.back()>>63) || CompareNumbers(input,modulus)>=0)
    return 0;
  const Montgomery context(modulus);
  Number value=input;
  // For e=2^k+1: k squarings followed by multiplication by the
  // original encoded signature. Do not convert into or out of this
  // representation as the ordinary RSA Power() helper does.
  for (u32 bits=exponent>>1;bits;bits>>=1)
    value=context.Multiply(value,value);
  value=context.Multiply(value,input);
  StoreNumber(value,recovered.data());
  EXCRYPT_SIG expected;
  ExCryptBnQwBeSigFormat(&expected,reinterpret_cast<const u8*>(hash->data()),
                       reinterpret_cast<const u8*>(salt->data()));
  return std::memcmp(recovered.data(),&expected,sizeof(expected))==0 ? 1 : 0;
}"""

def corrected_signature_verifier(source):
    if source.count(SIG_VERIFY_OLD)!=1 or SIG_VERIFY_NEW in source:
        raise ValueError("unexpected signature verification anchor")
    return source.replace(SIG_VERIFY_OLD,SIG_VERIFY_NEW,1)

PUBLIC_TEST_VECTORS=(
    (3,
     "e13ba01c923dfa01fe35b35d5ffcbf51c1b126368a83eeaa367bc0b359af052d470912d454a1a114f93e0d23be97b4521fb6289fa7f52c5044986ff28c4fd9001127e7b2fc546e56d6306ddd9e8e1463aab5120c04899e62b39978c4fb100cada2d503e35357dfb26eeaa5161c3cc02db0b3021e369bed66afc161796a6cca49c72a9e4fcea8117bc67d39c613f8cc4880e4dfd55cedf4f62cce9bea4c54803c8f2eefa1de959f0dca5229fce5616c71d56f909bc22888ee44dbe93fc31d9f66867a7183e1d7ad1121270371e1bb16a48eaa102679a95882ba9449be88109b680bd46fc966b9fad23477c02f76b441428c1bff7cbc3ccb934e10104b9ecd6511",
     "709d0d58fed8e454538d377412738071b2b38ebaadd8fe6b8143f5b5842ef71e0d14f504ae7becc1e2307f128bdb7cd4264bdb8ba3a2f8f443ffb4a7eec762a9acf555139840c8328bd8d6d41d6c546a6aa75f108630b812767dd1d3d7e45ffa714c6fbd414eedd9f7f1cde63691be48148ddf5af69cebc1eec45c1147be6f61e6ebcc5f65ea7037614aeb83c11e98fea37356de33fb176253118eeead96b50c0651f78dac386a4044abe7cac42e202fb5a055019f919d4f94ec8cd35fa2af2c934211b54e4e88cd1fce683c1bb021782a41fc7d86c9ebe97ea4a14ef2d05c9a518708c65f54bd361df3bc560de9bce22b6ed39d47c0c770813f965eee8e2f83"),
    (65537,
     "e56fad27678a07b55af45a125ddeb7e652d6e1ad7f16728e3b12b3111de6a9042a3a5a734ff885371e413f5f8a5a33740fc9888627faa338532443ae21a97ea7e327c4deacefa440c2d08765dd107fdcbbc76b61d72c6a72c8114c612c6d3703d1ca324d4065dfb798a8fe72287266b9253b10a8b5319c70d44b752c00a62e5dc1fa406330927e6fcc56eda9022e9e3b1ac931302ccf7c7a9c949cd96d1f8b27ad609be797d91fba89b2326928f56b67f1967a7c7bdca0ae5d40b176e9397df8c0756208967eb6bea20e86fff29d8f5c85575a82cbf6e882794dc6d0c7ff452721bc0c34e83a6f6050eb7c43abe90a15576ca9fe3292024afc5f37de94b01009",
     "78cfb6ae7df3c317c783fb73540711cb2206240c26f36c5cfcaf8a465e7cc48583be3fca51d043f2fb22873af152a05c567f02c4b3b757e6050a046ebf26e377bcd4fab78d3d107696a3678a2788a2bb0a648d5cbb359d761024c22e8607d0f0eef159fe2a0a4b6b11cb3ab34b06d6c6d97726baccae5d32e66d0ddde314e2cf5be18cf960853a30d6a2b63ec125cdb97055b4a8e4e51e8f8dda6b1fd2ccea19bfb99361ace039f3e976b6e322d949fe4e07d75e7c83d1868ec8f18fc65594935cf8af43ecefa05c3b587834e95e87b5fa69e2759c73c6156af783547ebe51f71c360c2679433420f0e6fc661d84048c14307427d81a1dc270c801dd59e5b756"),
)
TEST_HASH=bytes.fromhex("f71a4ac5cbaa6c4a4b06c3916559738be48c644d")
TEST_SALT=b"TEST_SIG01"

def reference_signature_result(signature,exponent,n):
    # Independent big-integer oracle: the original e-1 factors of R^-1.
    if not (0<=signature<n and exponent in (3,65537) and n.bit_length()==2048 and n&1):return None
    return pow(signature,exponent,n)*pow(1<<2048,1-exponent,n)%n

def signature_native_tests():
    tests=[]
    for e,n,s in PUBLIC_TEST_VECTORS:
        key=struct.pack(">IIQ",32,e,0)+guest_number(int(n,16))
        sig=guest_number(int(s,16))
        tests.append(r"""
REX_TEST_CASE("metro_io_runtime: original encoded public signature e=@E@",
              "[kernel][crypt][metro_io_runtime]") {
  KernelFixture fixture;
  fixture.RunOnGuestThread([](Caller& c) {
    const u32 key=c.Alloc(272),sig=c.Alloc(256),hash=c.Alloc(20),salt=c.Alloc(12);
    constexpr u32 key_words[]={
@KEY@
    };
    constexpr u32 sig_words[]={
@SIG@
    };
    constexpr u32 hash_words[]={
@HASH@
    };
    constexpr u32 salt_words[]={
@SALT@
    };
    for (u32 i=0;i<68;++i)c.Store32(key+i*4,key_words[i]);
    for (u32 i=0;i<64;++i)c.Store32(sig+i*4,sig_words[i]);
    for (u32 i=0;i<5;++i)c.Store32(hash+i*4,hash_words[i]);
    for (u32 i=0;i<3;++i)c.Store32(salt+i*4,salt_words[i]);
    REQUIRE(c.Kernel("XeCryptBnQwBeSigVerify",{sig,hash,salt,key})==1);
    CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{sig,hash,salt,key})==1);
    for (u32 i=0;i<64;++i)CHECK(c.Load32(sig+i*4)==sig_words[i]);
    for (u32 i=0;i<68;++i)CHECK(c.Load32(key+i*4)==key_words[i]);
    for (u32 i:{0u,7u,32u,63u}) {
      c.Store32(sig+i*4,sig_words[i]^1u);
      CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{sig,hash,salt,key})==0);
      c.Store32(sig+i*4,sig_words[i]);
    }
    c.Store32(hash,hash_words[0]^1u);
    CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{sig,hash,salt,key})==0);
    c.Store32(hash,hash_words[0]);
    c.Store32(salt,salt_words[0]^1u);
    CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{sig,hash,salt,key})==0);
    c.Store32(salt,salt_words[0]);
    c.Store32(key+4,5);
    CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{sig,hash,salt,key})==0);
    c.Store32(key+4,@E@);
    c.Store32(key+20,key_words[5]&~1u);
    CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{sig,hash,salt,key})==0);
    c.Store32(key+20,key_words[5]);
    for (u32 i=0;i<64;++i)c.Store32(sig+i*4,key_words[i+4]);
    CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{sig,hash,salt,key})==0);
    CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{0,hash,salt,key})==0);
    CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{sig,0xfffffffc,salt,key})==0);
    CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{sig,hash,0xfffffffc,key})==0);
    CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{sig,hash,salt,0xfffffffc})==0);
    for (u32 i=0;i<64;++i)c.Store32(sig+i*4,sig_words[i]);
    CHECK(c.Kernel("XeCryptBnQwBeSigVerify",{sig,hash,salt,key})==1);
  });
}
""".replace("@E@",str(e)).replace("@KEY@",c_words(key)).replace("@SIG@",c_words(sig)).replace("@HASH@",c_words(TEST_HASH)).replace("@SALT@",c_words(TEST_SALT+b"\0\0")))
    return "\n".join(tests)
