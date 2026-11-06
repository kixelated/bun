#include "root.h"
#include "rind.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

namespace Bun::Rind {

std::optional<BunRindKind> kindForCurveNid(int nid)
{
    switch (nid) {
    case NID_secp384r1:
        return BunRindKind::P384;
    case NID_secp521r1:
        return BunRindKind::P521;
    default:
        return std::nullopt;
    }
}

int curveNidForKind(BunRindKind kind)
{
    switch (kind) {
    case BunRindKind::P384:
        return NID_secp384r1;
    case BunRindKind::P521:
        return NID_secp521r1;
    default:
        return NID_undef;
    }
}

std::optional<BunRindHash> hashForDigest(const EVP_MD* md)
{
    switch (md ? EVP_MD_type(md) : NID_undef) {
    case NID_sha256:
        return BunRindHash::SHA256;
    case NID_sha384:
        return BunRindHash::SHA384;
    case NID_sha512:
        return BunRindHash::SHA512;
    default:
        return std::nullopt;
    }
}

const EVP_MD* digestForHash(BunRindHash hash)
{
    switch (hash) {
    case BunRindHash::SHA256:
        return EVP_sha256();
    case BunRindHash::SHA384:
        return EVP_sha384();
    case BunRindHash::SHA512:
        return EVP_sha512();
    }
    return nullptr;
}

std::optional<BunRindKind> kindOf(const EVP_PKEY* key)
{
    switch (key ? EVP_PKEY_id(key) : EVP_PKEY_NONE) {
    case EVP_PKEY_ED25519:
        return BunRindKind::Ed25519;
    case EVP_PKEY_X25519:
        return BunRindKind::X25519;
    case EVP_PKEY_EC: {
        const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(key);
        return ec ? kindForCurveNid(EC_GROUP_get_curve_name(EC_KEY_get0_group(ec))) : std::nullopt;
    }
    default:
        return std::nullopt;
    }
}

Key fromEVP(const EVP_PKEY* key, bool includePrivate)
{
    auto kind = kindOf(key);
    if (!kind)
        return nullptr;

    uint8_t publicKey[maxPublicKeySize];
    size_t publicLen = 0;
    uint8_t privateKey[66];
    size_t privateLen = 0;
    bool hasPrivate = false;

    if (isEc(*kind)) {
        const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(key);
        const EC_POINT* point = EC_KEY_get0_public_key(ec);
        if (!point)
            return nullptr;
        publicLen = EC_POINT_point2oct(EC_KEY_get0_group(ec), point, POINT_CONVERSION_UNCOMPRESSED, publicKey, sizeof(publicKey), nullptr);
        if (!publicLen)
            return nullptr;
        if (const BIGNUM* scalar = includePrivate ? EC_KEY_get0_private_key(ec) : nullptr) {
            privateLen = scalarSize(*kind);
            hasPrivate = BN_bn2bin_padded(privateKey, privateLen, scalar);
            if (!hasPrivate)
                return nullptr;
        }
    } else {
        publicLen = 32;
        if (!EVP_PKEY_get_raw_public_key(key, publicKey, &publicLen) || publicLen != 32)
            return nullptr;
        privateLen = 32;
        hasPrivate = includePrivate && EVP_PKEY_get_raw_private_key(key, privateKey, &privateLen) && privateLen == 32;
        ERR_clear_error();
    }

    Key result = adopt(hasPrivate
            ? Bun__Rind__keyFromPrivate(*kind, privateKey, privateLen, publicKey, publicLen)
            : Bun__Rind__keyFromPublic(*kind, publicKey, publicLen));
    OPENSSL_cleanse(privateKey, sizeof(privateKey));
    return result;
}

ncrypto::ECKeyPointer toECKey(const BunRindKey& key, bool includePrivate)
{
    auto kind = Bun__Rind__keyKind(&key);
    if (!isEc(kind))
        return {};
    uint8_t publicKey[maxPublicKeySize];
    size_t publicLen = Bun__Rind__keyPublic(&key, publicKey, sizeof(publicKey));
    uint8_t privateKey[66];
    size_t privateLen = includePrivate ? Bun__Rind__keyPrivate(&key, privateKey, sizeof(privateKey)) : 0;

    auto ec = ncrypto::ECKeyPointer::NewByCurveName(curveNidForKind(kind));
    const EC_GROUP* group = ec ? EC_KEY_get0_group(ec.get()) : nullptr;
    auto point = ncrypto::ECPointPointer::New(group);
    bool ok = ec && point && point.setFromBuffer({ .data = publicKey, .len = publicLen }, group)
        && EC_KEY_set_public_key(ec.get(), point.get());
    if (ok && privateLen) {
        ncrypto::BignumPointer scalar(privateKey, privateLen);
        ok = scalar && EC_KEY_set_private_key(ec.get(), scalar.get());
    }
    OPENSSL_cleanse(privateKey, sizeof(privateKey));
    if (!ok)
        return {};
    EC_KEY_set_asn1_flag(ec.get(), OPENSSL_EC_NAMED_CURVE);
    return ec;
}

ncrypto::EVPKeyPointer toEVP(const BunRindKey& key, bool includePrivate)
{
    auto kind = Bun__Rind__keyKind(&key);
    ncrypto::EVPKeyPointer result;
    if (isEc(kind)) {
        auto ec = toECKey(key, includePrivate);
        if (ec) {
            result = ncrypto::EVPKeyPointer::New();
            if (!result || !result.set(ec))
                result.reset();
        }
        return result;
    }

    int id = kind == BunRindKind::Ed25519 ? EVP_PKEY_ED25519 : EVP_PKEY_X25519;
    uint8_t privateKey[32];
    if (includePrivate && Bun__Rind__keyPrivate(&key, privateKey, sizeof(privateKey))) {
        result = ncrypto::EVPKeyPointer::NewRawPrivate(id, { .data = privateKey, .len = sizeof(privateKey) });
        OPENSSL_cleanse(privateKey, sizeof(privateKey));
        return result;
    }
    uint8_t publicKey[32];
    size_t publicLen = Bun__Rind__keyPublic(&key, publicKey, sizeof(publicKey));
    return ncrypto::EVPKeyPointer::NewRawPublic(id, { .data = publicKey, .len = publicLen });
}

WTF::Vector<uint8_t> publicKey(const BunRindKey& key)
{
    uint8_t out[maxPublicKeySize];
    return WTF::Vector<uint8_t>(std::span<const uint8_t> { out, Bun__Rind__keyPublic(&key, out, sizeof(out)) });
}

WTF::Vector<uint8_t> privateKey(const BunRindKey& key)
{
    uint8_t out[66];
    WTF::Vector<uint8_t> result(std::span<const uint8_t> { out, Bun__Rind__keyPrivate(&key, out, sizeof(out)) });
    OPENSSL_cleanse(out, sizeof(out));
    return result;
}

WTF::Vector<uint8_t> exportKey(const BunRindKey& key, BunRindFormat format)
{
    uint8_t out[maxEncodedSize];
    WTF::Vector<uint8_t> result(std::span<const uint8_t> { out, Bun__Rind__keyExport(&key, format, out, sizeof(out)) });
    OPENSSL_cleanse(out, sizeof(out));
    return result;
}

ncrypto::DataPointer fixedToDer(std::span<const uint8_t> fixed)
{
    size_t n = fixed.size() / 2;
    std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(ECDSA_SIG_new(), ECDSA_SIG_free);
    BIGNUM* r = BN_bin2bn(fixed.data(), n, nullptr);
    BIGNUM* s = BN_bin2bn(fixed.data() + n, n, nullptr);
    if (!sig || !r || !s || !ECDSA_SIG_set0(sig.get(), r, s)) {
        BN_free(r);
        BN_free(s);
        return {};
    }
    uint8_t* der = nullptr;
    size_t derLen = 0;
    if (!ECDSA_SIG_to_bytes(&der, &derLen, sig.get()))
        return {};
    return ncrypto::DataPointer(der, derLen);
}

bool derToFixed(std::span<const uint8_t> der, size_t n, uint8_t* fixed)
{
    std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(ECDSA_SIG_from_bytes(der.data(), der.size()), ECDSA_SIG_free);
    uint8_t* reencoded = nullptr;
    size_t reencodedLen = 0;
    bool canonical = sig && ECDSA_SIG_to_bytes(&reencoded, &reencodedLen, sig.get())
        && reencodedLen == der.size() && !memcmp(reencoded, der.data(), reencodedLen);
    OPENSSL_free(reencoded);
    ERR_clear_error();
    if (!canonical)
        return false;
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig.get(), &r, &s);
    return BN_bn2bin_padded(fixed, n, r) && BN_bn2bin_padded(fixed + n, n, s);
}

} // namespace Bun::Rind
