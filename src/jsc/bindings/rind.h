#pragma once

// Ed25519, and ECDSA on P-384 and P-521, run on rind (src/runtime/crypto/rind.rs),
// which measures faster than BoringSSL at each. BoringSSL still parses and
// encodes these keys: a rind key is built from the raw key it holds.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include "ncrypto.h"

struct BunRindEd25519Key;
struct BunRindEcdsaKey;

// Each curve signs with the SHA-2 hash of its size, and a signature is
// r || s, each the curve's size (IEEE P1363).
enum class BunRindCurve : uint8_t {
    P384 = 0,
    P521 = 1,
};

extern "C" {
BunRindEd25519Key* Bun__Rind__ed25519FromSeed(const uint8_t seed[32], uint8_t outPublic[32]);
BunRindEd25519Key* Bun__Rind__ed25519Generate(uint8_t outSeed[32], uint8_t outPublic[32]);
void Bun__Rind__ed25519Sign(const BunRindEd25519Key*, const uint8_t* message, size_t messageLen, uint8_t outSignature[64]);
bool Bun__Rind__ed25519Verify(const uint8_t publicKey[32], const uint8_t* message, size_t messageLen, const uint8_t signature[64]);
void Bun__Rind__ed25519Free(BunRindEd25519Key*);

BunRindEcdsaKey* Bun__Rind__ecdsaFromScalar(BunRindCurve, const uint8_t* scalar, size_t scalarLen, const uint8_t* point, size_t pointLen);
BunRindEcdsaKey* Bun__Rind__ecdsaGenerate(BunRindCurve, uint8_t* outScalar, uint8_t* outPoint);
bool Bun__Rind__ecdsaSign(const BunRindEcdsaKey*, const uint8_t* message, size_t messageLen, uint8_t* outSignature, size_t outSignatureLen);
bool Bun__Rind__ecdsaVerify(BunRindCurve, const uint8_t* point, size_t pointLen, const uint8_t* message, size_t messageLen, const uint8_t* signature, size_t signatureLen);
void Bun__Rind__ecdsaFree(BunRindEcdsaKey*);
}

namespace Bun::Rind {

struct Ed25519KeyDeleter {
    void operator()(BunRindEd25519Key* key) const { Bun__Rind__ed25519Free(key); }
};
using Ed25519Key = std::unique_ptr<BunRindEd25519Key, Ed25519KeyDeleter>;

struct EcdsaKeyDeleter {
    void operator()(BunRindEcdsaKey* key) const { Bun__Rind__ecdsaFree(key); }
};
using EcdsaKey = std::unique_ptr<BunRindEcdsaKey, EcdsaKeyDeleter>;

// The curve's size in bytes: its scalar, and each half of a signature.
constexpr size_t scalarSize(BunRindCurve curve) { return curve == BunRindCurve::P384 ? 48 : 66; }

// The rind curve for a BoringSSL curve NID, if rind runs it.
std::optional<BunRindCurve> curveForNid(int nid);

// The rind curve of an EC key, if rind runs it and `digestNid` is the hash it signs with.
std::optional<BunRindCurve> curveForSigning(const EC_KEY*, int digestNid);

// The rind key pair for an EC private key on a curve rind runs.
EcdsaKey ecdsaKey(const EC_KEY*);

// Generates a key pair into `key`, an EC key without one on a curve rind runs,
// and returns rind's copy of it.
EcdsaKey generateEcdsaKey(EC_KEY* key);

// Verifies r || s over `message` with an EC public key.
bool ecdsaVerify(BunRindCurve, const EC_KEY*, std::span<const uint8_t> message, std::span<const uint8_t> signature);

} // namespace Bun::Rind
