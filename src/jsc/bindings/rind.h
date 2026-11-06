#pragma once

// Ed25519, X25519, and ECDSA and ECDH on P-384 and P-521 run on rind
// (src/runtime/crypto/rind.rs), which measures faster than BoringSSL at each.
// P-256 stays on BoringSSL: rind generates its keys slower and verifies no
// faster.
// rind parses and writes these keys in the encodings OpenSSL, BoringSSL, and
// Node write; any other encoding is BoringSSL's to parse, as before, and the
// rind key is then loaded from its raw parts. A BoringSSL key is built from
// the rind key only for the paths still on BoringSSL.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <wtf/Vector.h>
#include "ncrypto.h"

struct BunRindKey;
struct BunRindDigestContext;
struct BunRindDigest;

enum class BunRindKind : uint8_t {
    Ed25519 = 0,
    X25519 = 1,
    P384 = 3,
    P521 = 4,
    // Parsing only: whichever kind the encoding names.
    Any = 255,
};

// The hashes rind signs and verifies ECDSA over.
enum class BunRindHash : uint8_t {
    SHA256 = 0,
    SHA384 = 1,
    SHA512 = 2,
};

enum class BunRindFormat : uint8_t {
    PKCS8 = 0,
    SPKI = 1,
    SEC1 = 2,
};

extern "C" {
BunRindKey* Bun__Rind__keyGenerate(BunRindKind);
BunRindKey* Bun__Rind__keyParse(BunRindKind, BunRindFormat, const uint8_t* der, size_t derLen);
BunRindKey* Bun__Rind__keyFromPublic(BunRindKind, const uint8_t* publicKey, size_t publicKeyLen);
BunRindKey* Bun__Rind__keyFromPrivate(BunRindKind, const uint8_t* privateKey, size_t privateKeyLen, const uint8_t* publicKey, size_t publicKeyLen);
BunRindKey* Bun__Rind__keyPublicHalf(const BunRindKey*);
void Bun__Rind__keyFree(BunRindKey*);
BunRindKind Bun__Rind__keyKind(const BunRindKey*);
bool Bun__Rind__keyIsPrivate(const BunRindKey*);
size_t Bun__Rind__keyPublic(const BunRindKey*, uint8_t* out, size_t cap);
size_t Bun__Rind__keyPrivate(const BunRindKey*, uint8_t* out, size_t cap);
size_t Bun__Rind__keyExport(const BunRindKey*, BunRindFormat, uint8_t* out, size_t cap);

size_t Bun__Rind__sign(const BunRindKey*, BunRindHash, const uint8_t* message, size_t messageLen, uint8_t* out, size_t cap);
bool Bun__Rind__verify(const BunRindKey*, BunRindHash, const uint8_t* message, size_t messageLen, const uint8_t* signature, size_t signatureLen);

BunRindDigestContext* Bun__Rind__digestNew(BunRindHash);
void Bun__Rind__digestUpdate(BunRindDigestContext*, const uint8_t* data, size_t len);
BunRindDigest* Bun__Rind__digestFinish(BunRindDigestContext*);
void Bun__Rind__digestContextFree(BunRindDigestContext*);
size_t Bun__Rind__digestBytes(const BunRindDigest*, uint8_t out[64]);
void Bun__Rind__digestFree(BunRindDigest*);
size_t Bun__Rind__signDigest(const BunRindKey*, const BunRindDigest*, uint8_t* out, size_t cap);
bool Bun__Rind__verifyDigest(const BunRindKey*, const BunRindDigest*, const uint8_t* signature, size_t signatureLen);

size_t Bun__Rind__agree(const BunRindKey*, const uint8_t* peer, size_t peerLen, uint8_t* out, size_t cap);
bool Bun__Rind__x25519(const uint8_t privateKey[32], const uint8_t peer[32], uint8_t out[32]);
}

namespace Bun::Rind {

// A rind key, immutable once made, shared by every object that holds it.
using Key = std::shared_ptr<const BunRindKey>;
inline Key adopt(BunRindKey* key)
{
    if (!key)
        return nullptr;
    return Key(key, [](const BunRindKey* key) { Bun__Rind__keyFree(const_cast<BunRindKey*>(key)); });
}

struct DigestContextDeleter {
    void operator()(BunRindDigestContext* context) const { Bun__Rind__digestContextFree(context); }
};
using DigestContext = std::unique_ptr<BunRindDigestContext, DigestContextDeleter>;

struct DigestDeleter {
    void operator()(BunRindDigest* digest) const { Bun__Rind__digestFree(digest); }
};
using Digest = std::unique_ptr<BunRindDigest, DigestDeleter>;

// The longest encoding of a key here, P-521's PKCS#8, and of a signature, P-521's r || s.
constexpr size_t maxEncodedSize = 256;
constexpr size_t maxSignatureSize = 2 * 66;
// A raw public key: 32 bytes, or P-521's uncompressed point at most.
constexpr size_t maxPublicKeySize = 1 + 2 * 66;

inline bool isEc(BunRindKind kind) { return kind == BunRindKind::P384 || kind == BunRindKind::P521; }

// A NIST curve's size in bytes: its scalar, and each half of a signature.
constexpr size_t scalarSize(BunRindKind kind) { return kind == BunRindKind::P384 ? 48 : 66; }

// The kind for a BoringSSL curve NID, if rind runs it.
std::optional<BunRindKind> kindForCurveNid(int nid);
int curveNidForKind(BunRindKind);

// The rind hash for a BoringSSL digest, if rind signs over it.
std::optional<BunRindHash> hashForDigest(const EVP_MD*);
const EVP_MD* digestForHash(BunRindHash);

// The kind of a BoringSSL key, if rind runs it.
std::optional<BunRindKind> kindOf(const EVP_PKEY*);

// Parses `der` with rind if it is an encoding rind writes; otherwise null,
// and the caller takes BoringSSL's path.
inline Key parse(BunRindKind kind, BunRindFormat format, std::span<const uint8_t> der)
{
    return adopt(Bun__Rind__keyParse(kind, format, der.data(), der.size()));
}

// rind's copy of a key BoringSSL holds, of a kind rind runs; null otherwise.
// It loads the key again, so it is for keys BoringSSL had to parse.
Key fromEVP(const EVP_PKEY*, bool includePrivate);

// BoringSSL's copy of a rind key, for the paths still on BoringSSL. A NIST
// curve's is built from the scalar and point without another scalar
// multiplication.
ncrypto::EVPKeyPointer toEVP(const BunRindKey&, bool includePrivate);
// BoringSSL's EC_KEY for a NIST curve's rind key, built the same way; null for any other kind.
ncrypto::ECKeyPointer toECKey(const BunRindKey&, bool includePrivate);

// The raw public key: 32 bytes, or a NIST curve's uncompressed point.
WTF::Vector<uint8_t> publicKey(const BunRindKey&);
// The raw private key: Ed25519's seed, X25519's 32 bytes, or a NIST curve's scalar.
WTF::Vector<uint8_t> privateKey(const BunRindKey&);
// The key in `format`; empty if it has no such encoding.
WTF::Vector<uint8_t> exportKey(const BunRindKey&, BunRindFormat);

// r || s as DER, as BoringSSL's ECDSA_SIG_to_bytes writes it.
ncrypto::DataPointer fixedToDer(std::span<const uint8_t> fixed);
// A DER ECDSA signature as r || s of the curve's size, refused unless it
// re-encodes to itself, as BoringSSL's ECDSA_verify requires.
bool derToFixed(std::span<const uint8_t> der, size_t scalarSize, uint8_t* fixed);

} // namespace Bun::Rind
