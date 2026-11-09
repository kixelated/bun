/*
 * Copyright (C) 2020 Sony Interactive Entertainment Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "CryptoKeyEC.h"
#include "../wtf-bindings.h"

#if ENABLE(WEB_CRYPTO)

#include "JsonWebKey.h"
#include "OpenSSLUtilities.h"
#include <wtf/text/Base64.h>

namespace WebCore {

static int curveIdentifier(CryptoKeyEC::NamedCurve curve)
{
    switch (curve) {
    case CryptoKeyEC::NamedCurve::P256:
        return NID_X9_62_prime256v1;
    case CryptoKeyEC::NamedCurve::P384:
        return NID_secp384r1;
    case CryptoKeyEC::NamedCurve::P521:
        return NID_secp521r1;
    }

    ASSERT_NOT_REACHED();
    return NID_undef;
}

static size_t curveSize(CryptoKeyEC::NamedCurve curve)
{
    switch (curve) {
    case CryptoKeyEC::NamedCurve::P256:
        return 256;
    case CryptoKeyEC::NamedCurve::P384:
        return 384;
    case CryptoKeyEC::NamedCurve::P521:
        return 521;
    }

    ASSERT_NOT_REACHED();
    return 0;
}

static ECKeyPtr createECKey(CryptoKeyEC::NamedCurve curve)
{
    auto key = ECKeyPtr(EC_KEY_new_by_curve_name(curveIdentifier(curve)));
    if (key) {
        // OPENSSL_EC_NAMED_CURVE needs to be set to export the key with the curve name, not with the curve parameters.
        EC_KEY_set_asn1_flag(key.get(), OPENSSL_EC_NAMED_CURVE);
    }
    return key;
}

// This function verifies that the group represents the named curve.
static bool verifyCurve(const EC_GROUP* group, CryptoKeyEC::NamedCurve curve)
{
    if (!group)
        return false;

    auto key = createECKey(curve);
    if (!key)
        return false;

    return !EC_GROUP_cmp(group, EC_KEY_get0_group(key.get()), nullptr);
}

size_t CryptoKeyEC::keySizeInBits() const
{
    // EVP_PKEY_size() returns the size of DER-encoded key and cannot be used for this function's purpose.
    // Instead we resolve the key size by CryptoKeyEC::NamedCurve.
    size_t size = curveSize(m_curve);
    return size;
}

bool CryptoKeyEC::platformSupportedCurve(NamedCurve curve)
{
    return curve == NamedCurve::P256 || curve == NamedCurve::P384 || curve == NamedCurve::P521;
}

std::optional<CryptoKeyPair> CryptoKeyEC::platformGeneratePair(CryptoAlgorithmIdentifier identifier, NamedCurve curve, bool extractable, CryptoKeyUsageBitmap usages)
{
    auto privateKey = Bun::Rind::adopt(Bun__Rind__keyGenerate(rindKind(curve)));
    if (!privateKey)
        return std::nullopt;
    auto publicKey = Bun::Rind::adopt(Bun__Rind__keyPublicHalf(privateKey.get()));
    return CryptoKeyPair {
        CryptoKeyEC::create(identifier, curve, CryptoKeyType::Public, WTF::move(publicKey), true, usages),
        CryptoKeyEC::create(identifier, curve, CryptoKeyType::Private, WTF::move(privateKey), extractable, usages),
    };
}

// A key BoringSSL parsed, with rind's copy loaded from its raw parts.
static RefPtr<CryptoKeyEC> createFromPlatformKey(CryptoAlgorithmIdentifier identifier, CryptoKeyEC::NamedCurve curve, CryptoKeyType type, EvpPKeyPtr&& pkey, bool extractable, CryptoKeyUsageBitmap usages)
{
    auto rindKey = Bun::Rind::fromEVP(pkey.get(), type == CryptoKeyType::Private);
    if (!rindKey)
        return nullptr;
    return CryptoKeyEC::create(identifier, curve, type, WTF::move(rindKey), extractable, usages, WTF::move(pkey));
}

RefPtr<CryptoKeyEC> CryptoKeyEC::platformImportRaw(CryptoAlgorithmIdentifier identifier, NamedCurve curve, Vector<uint8_t>&& keyData, bool extractable, CryptoKeyUsageBitmap usages)
{
    auto key = Bun::Rind::adopt(Bun__Rind__keyFromPublic(rindKind(curve), keyData.begin(), keyData.size()));
    if (!key)
        return nullptr;
    return create(identifier, curve, CryptoKeyType::Public, WTF::move(key), extractable, usages);
}

RefPtr<CryptoKeyEC> CryptoKeyEC::platformImportJWKPublic(CryptoAlgorithmIdentifier identifier, NamedCurve curve, Vector<uint8_t>&& x, Vector<uint8_t>&& y, bool extractable, CryptoKeyUsageBitmap usages)
{
    size_t size = Bun::Rind::scalarSize(rindKind(curve));
    if (x.size() == size && y.size() == size) {
        Vector<uint8_t> point { 0x04 };
        point.appendVector(x);
        point.appendVector(y);
        return platformImportRaw(identifier, curve, WTF::move(point), extractable, usages);
    }

    // Coordinates of another length are BoringSSL's to read, as before.
    auto key = createECKey(curve);
    if (!key)
        return nullptr;

    auto group = EC_KEY_get0_group(key.get());
    auto point = ECPointPtr(EC_POINT_new(group));

    // Currently we only support elliptic curves over GF(p).
    if (EC_POINT_set_affine_coordinates_GFp(group, point.get(), convertToBigNumber(x).get(), convertToBigNumber(y).get(), nullptr) <= 0)
        return nullptr;

    if (EC_KEY_set_public_key(key.get(), point.get()) <= 0)
        return nullptr;

    if (EC_KEY_check_key(key.get()) <= 0)
        return nullptr;

    auto pkey = EvpPKeyPtr(EVP_PKEY_new());
    if (EVP_PKEY_set1_EC_KEY(pkey.get(), key.get()) <= 0)
        return nullptr;

    return createFromPlatformKey(identifier, curve, CryptoKeyType::Public, WTF::move(pkey), extractable, usages);
}

RefPtr<CryptoKeyEC> CryptoKeyEC::platformImportJWKPrivate(CryptoAlgorithmIdentifier identifier, NamedCurve curve, Vector<uint8_t>&& x, Vector<uint8_t>&& y, Vector<uint8_t>&& d, bool extractable, CryptoKeyUsageBitmap usages)
{
    size_t size = Bun::Rind::scalarSize(rindKind(curve));
    if (x.size() == size && y.size() == size && d.size() == size) {
        Vector<uint8_t> point { 0x04 };
        point.appendVector(x);
        point.appendVector(y);
        auto key = Bun::Rind::adopt(Bun__Rind__keyFromPrivate(rindKind(curve), d.begin(), d.size(), point.begin(), point.size()));
        if (!key)
            return nullptr;
        return create(identifier, curve, CryptoKeyType::Private, WTF::move(key), extractable, usages);
    }

    // Values of another length are BoringSSL's to read, as before.
    auto key = createECKey(curve);
    if (!key)
        return nullptr;

    auto group = EC_KEY_get0_group(key.get());
    auto point = ECPointPtr(EC_POINT_new(group));

    // Currently we only support elliptic curves over GF(p).
    if (EC_POINT_set_affine_coordinates_GFp(group, point.get(), convertToBigNumber(x).get(), convertToBigNumber(y).get(), nullptr) <= 0)
        return nullptr;

    if (EC_KEY_set_public_key(key.get(), point.get()) <= 0)
        return nullptr;

    if (EC_KEY_set_private_key(key.get(), convertToBigNumber(d).get()) <= 0)
        return nullptr;

    if (EC_KEY_check_key(key.get()) <= 0)
        return nullptr;

    auto pkey = EvpPKeyPtr(EVP_PKEY_new());
    if (EVP_PKEY_set1_EC_KEY(pkey.get(), key.get()) <= 0)
        return nullptr;

    return createFromPlatformKey(identifier, curve, CryptoKeyType::Private, WTF::move(pkey), extractable, usages);
}

static const ASN1_OBJECT* ecPublicKeyIdentifier()
{
    static ASN1_OBJECT* oid = OBJ_txt2obj("1.2.840.10045.2.1", 1);
    return oid;
}

static const ASN1_OBJECT* ecDHIdentifier()
{
    static ASN1_OBJECT* oid = OBJ_txt2obj("1.3.132.1.12", 1);
    return oid;
}

static bool supportedAlgorithmIdentifier(CryptoAlgorithmIdentifier identifier, const ASN1_OBJECT* oid)
{
    switch (identifier) {
    case CryptoAlgorithmIdentifier::ECDSA:
        // ECDSA only supports id-ecPublicKey algorithms for imported keys.
        if (!OBJ_cmp(oid, ecPublicKeyIdentifier()))
            return true;
        return false;
    case CryptoAlgorithmIdentifier::ECDH:
        // ECDH supports both id-ecPublicKey and id-ecDH algorithms for imported keys.
        if (!OBJ_cmp(oid, ecPublicKeyIdentifier()))
            return true;
        if (!OBJ_cmp(oid, ecDHIdentifier()))
            return true;
        return false;
    default:
        ASSERT_NOT_REACHED();
        return false;
    }
}

RefPtr<CryptoKeyEC> CryptoKeyEC::platformImportSpki(CryptoAlgorithmIdentifier identifier, NamedCurve curve, Vector<uint8_t>&& keyData, bool extractable, CryptoKeyUsageBitmap usages, bool* keyTypeMismatch, bool* curveMismatch)
{
    if (auto key = Bun::Rind::parse(rindKind(curve), BunRindFormat::SPKI, keyData.span()))
        return create(identifier, curve, CryptoKeyType::Public, WTF::move(key), extractable, usages);

    // In this function we extract the subjectPublicKey after verifying that the algorithm in the SPKI data
    // match the given identifier and curve. Then construct an EC key with the named curve and set the public key.

    // SubjectPublicKeyInfo  ::=  SEQUENCE  {
    //   algorithm         AlgorithmIdentifier,
    //   subjectPublicKey  BIT STRING
    // }

    const uint8_t* ptr = keyData.begin();
    auto subjectPublicKeyInfo = ASN1SequencePtr(d2i_ASN1_SEQUENCE_ANY(nullptr, &ptr, keyData.size()));
    if (!subjectPublicKeyInfo)
        return nullptr;
    if (ptr - keyData.begin() != (ptrdiff_t)keyData.size())
        return nullptr;

    if (sk_ASN1_TYPE_num(subjectPublicKeyInfo.get()) != 2)
        return nullptr;

    ASN1_TYPE* value = sk_ASN1_TYPE_value(subjectPublicKeyInfo.get(), 0);
    if (value->type != V_ASN1_SEQUENCE)
        return nullptr;

    // AlgorithmIdentifier  ::=  SEQUENCE  {
    //     algorithm   OBJECT IDENTIFIER,
    //     parameters  ANY DEFINED BY algorithm OPTIONAL
    // }

    ptr = value->value.sequence->data;
    auto algorithm = ASN1SequencePtr(d2i_ASN1_SEQUENCE_ANY(nullptr, &ptr, value->value.sequence->length));
    if (!algorithm)
        return nullptr;

    // A well-formed AlgorithmIdentifier whose shape or OID does not match EC is a key
    // of another type; gate on the real parser so garbage is not misreported as such.
    auto reportKeyTypeMismatch = [&] {
        if (keyTypeMismatch) {
            const uint8_t* p = keyData.begin();
            if (EvpPKeyPtr(d2i_PUBKEY(nullptr, &p, keyData.size())))
                *keyTypeMismatch = true;
        }
    };

    if (sk_ASN1_TYPE_num(algorithm.get()) != 2) {
        reportKeyTypeMismatch();
        return nullptr;
    }

    value = sk_ASN1_TYPE_value(algorithm.get(), 0);
    if (value->type != V_ASN1_OBJECT)
        return nullptr;

    if (!supportedAlgorithmIdentifier(identifier, value->value.object)) {
        reportKeyTypeMismatch();
        return nullptr;
    }

    // ECParameters ::= CHOICE {
    //  namedCurve         OBJECT IDENTIFIER
    //  -- implicitCurve   null
    //  -- specifiedCurve  SpecifiedECDomain
    // }
    //
    // Only "namedCurve" is supported.
    value = sk_ASN1_TYPE_value(algorithm.get(), 1);
    if (value->type != V_ASN1_OBJECT)
        return nullptr;

    int curveNID = OBJ_obj2nid(value->value.object);
    if (curveNID != curveIdentifier(curve)) {
        if (curveMismatch)
            *curveMismatch = true;
        return nullptr;
    }

    // subjectPublicKey must be a BIT STRING.
    value = sk_ASN1_TYPE_value(subjectPublicKeyInfo.get(), 1);
    if (value->type != V_ASN1_BIT_STRING)
        return nullptr;

    ASN1_BIT_STRING* bitString = value->value.bit_string;

    // The SPKI data has been verified at this point. We prepare platform data next.
    auto key = createECKey(curve);
    if (!key)
        return nullptr;

    auto group = EC_KEY_get0_group(key.get());
    if (!group)
        return nullptr;

    auto point = ECPointPtr(EC_POINT_new(group));
    if (!point)
        return nullptr;

    if (EC_POINT_oct2point(group, point.get(), bitString->data, bitString->length, 0) <= 0)
        return nullptr;

    if (EC_KEY_set_public_key(key.get(), point.get()) <= 0)
        return nullptr;

    if (EC_KEY_check_key(key.get()) <= 0)
        return nullptr;

    EC_KEY_set_asn1_flag(key.get(), OPENSSL_EC_NAMED_CURVE);

    auto pkey = EvpPKeyPtr(EVP_PKEY_new());
    if (EVP_PKEY_set1_EC_KEY(pkey.get(), key.get()) <= 0)
        return nullptr;

    return createFromPlatformKey(identifier, curve, CryptoKeyType::Public, WTF::move(pkey), extractable, usages);
}

RefPtr<CryptoKeyEC> CryptoKeyEC::platformImportPkcs8(CryptoAlgorithmIdentifier identifier, NamedCurve curve, Vector<uint8_t>&& keyData, bool extractable, CryptoKeyUsageBitmap usages, bool* keyTypeMismatch, bool* curveMismatch)
{
    if (auto key = Bun::Rind::parse(rindKind(curve), BunRindFormat::PKCS8, keyData.span()))
        return create(identifier, curve, CryptoKeyType::Private, WTF::move(key), extractable, usages);

    // We need a local pointer variable to pass to d2i (DER to internal) functions().
    const uint8_t* ptr = keyData.begin();

    // We use d2i_PKCS8_PRIV_KEY_INFO() to import a private key.
    auto p8inf = PKCS8PrivKeyInfoPtr(d2i_PKCS8_PRIV_KEY_INFO(nullptr, &ptr, keyData.size()));
    if (!p8inf)
        return nullptr;
    if (ptr - keyData.begin() != (ptrdiff_t)keyData.size())
        return nullptr;

    auto pkey = EvpPKeyPtr(EVP_PKCS82PKEY(p8inf.get()));
    if (!pkey)
        return nullptr;
    if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_EC) {
        if (keyTypeMismatch)
            *keyTypeMismatch = true;
        return nullptr;
    }

    auto ecKey = EVP_PKEY_get0_EC_KEY(pkey.get());
    if (!ecKey)
        return nullptr;

    if (EC_KEY_check_key(ecKey) <= 0)
        return nullptr;

    if (!verifyCurve(EC_KEY_get0_group(ecKey), curve)) {
        if (curveMismatch)
            *curveMismatch = true;
        return nullptr;
    }

    EC_KEY_set_asn1_flag(ecKey, OPENSSL_EC_NAMED_CURVE);

    return createFromPlatformKey(identifier, curve, CryptoKeyType::Private, WTF::move(pkey), extractable, usages);
}

Vector<uint8_t> CryptoKeyEC::platformExportRaw() const
{
    return Bun::Rind::publicKey(*m_rindKey);
}

bool CryptoKeyEC::platformAddFieldElements(JsonWebKey& jwk) const
{
    size_t size = Bun::Rind::scalarSize(rindKind(m_curve));
    auto point = Bun::Rind::publicKey(*m_rindKey);
    if (point.size() != 1 + 2 * size)
        return false;
    jwk.x = Bun::base64URLEncodeToString(Vector<uint8_t>(point.subspan(1, size)));
    jwk.y = Bun::base64URLEncodeToString(Vector<uint8_t>(point.subspan(1 + size, size)));

    if (type() == Type::Private) {
        auto d = Bun::Rind::privateKey(*m_rindKey);
        if (d.size() != size)
            return false;
        jwk.d = Bun::base64URLEncodeToString(d);
        OPENSSL_cleanse(d.begin(), d.size());
    }
    return true;
}

Vector<uint8_t> CryptoKeyEC::platformExportSpki() const
{
    if (type() != CryptoKeyType::Public)
        return {};
    return Bun::Rind::exportKey(*m_rindKey, BunRindFormat::SPKI);
}

Vector<uint8_t> CryptoKeyEC::platformExportPkcs8() const
{
    if (type() != CryptoKeyType::Private)
        return {};
    return Bun::Rind::exportKey(*m_rindKey, BunRindFormat::PKCS8);
}

} // namespace WebCore

#endif // ENABLE(WEB_CRYPTO)
