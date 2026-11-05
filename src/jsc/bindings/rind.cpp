#include "root.h"
#include "rind.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

namespace Bun::Rind {

std::optional<BunRindCurve> curveForNid(int nid)
{
    switch (nid) {
    case NID_secp384r1:
        return BunRindCurve::P384;
    case NID_secp521r1:
        return BunRindCurve::P521;
    default:
        return std::nullopt;
    }
}

std::optional<BunRindCurve> curveForSigning(const EC_KEY* key, int digestNid)
{
    if (!key)
        return std::nullopt;
    auto curve = curveForNid(EC_GROUP_get_curve_name(EC_KEY_get0_group(key)));
    if (!curve)
        return std::nullopt;
    if (digestNid != (*curve == BunRindCurve::P384 ? NID_sha384 : NID_sha512))
        return std::nullopt;
    return curve;
}

// An uncompressed point is at most 1 + 2 * 66 bytes, for P-521.
static constexpr size_t maxPointSize = 1 + 2 * 66;

static size_t encodePoint(const EC_KEY* key, uint8_t (&out)[maxPointSize])
{
    const EC_POINT* point = EC_KEY_get0_public_key(key);
    if (!point)
        return 0;
    return EC_POINT_point2oct(EC_KEY_get0_group(key), point, POINT_CONVERSION_UNCOMPRESSED, out, sizeof(out), nullptr);
}

EcdsaKey ecdsaKey(const EC_KEY* key)
{
    if (!key)
        return nullptr;
    auto curve = curveForNid(EC_GROUP_get_curve_name(EC_KEY_get0_group(key)));
    const BIGNUM* privateKey = EC_KEY_get0_private_key(key);
    if (!curve || !privateKey)
        return nullptr;
    uint8_t scalar[66];
    size_t scalarLen = scalarSize(*curve);
    uint8_t point[maxPointSize];
    size_t pointLen = encodePoint(key, point);
    if (!pointLen || !BN_bn2bin_padded(scalar, scalarLen, privateKey))
        return nullptr;
    EcdsaKey result(Bun__Rind__ecdsaFromScalar(*curve, scalar, scalarLen, point, pointLen));
    OPENSSL_cleanse(scalar, sizeof(scalar));
    return result;
}

EcdsaKey generateEcdsaKey(EC_KEY* key)
{
    if (!key)
        return nullptr;
    const EC_GROUP* group = EC_KEY_get0_group(key);
    auto curve = curveForNid(EC_GROUP_get_curve_name(group));
    if (!curve)
        return nullptr;
    uint8_t scalar[66];
    size_t scalarLen = scalarSize(*curve);
    uint8_t point[maxPointSize];
    size_t pointLen = 1 + 2 * scalarLen;
    EcdsaKey rind(Bun__Rind__ecdsaGenerate(*curve, scalar, point));
    if (!rind)
        return nullptr;

    ncrypto::BignumPointer privateKey(scalar, scalarLen);
    OPENSSL_cleanse(scalar, sizeof(scalar));
    auto publicKey = ncrypto::ECPointPointer::New(group);
    if (!privateKey || !publicKey
        || !publicKey.setFromBuffer({ .data = point, .len = pointLen }, group)
        || !EC_KEY_set_private_key(key, privateKey.get())
        || !EC_KEY_set_public_key(key, publicKey.get()))
        return nullptr;
    return rind;
}

bool ecdsaVerify(BunRindCurve curve, const EC_KEY* key, std::span<const uint8_t> message, std::span<const uint8_t> signature)
{
    uint8_t point[maxPointSize];
    size_t pointLen = encodePoint(key, point);
    if (!pointLen)
        return false;
    return Bun__Rind__ecdsaVerify(curve, point, pointLen, message.data(), message.size(), signature.data(), signature.size());
}

} // namespace Bun::Rind
