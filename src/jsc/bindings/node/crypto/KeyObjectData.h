#pragma once

#include "root.h"
#include "ncrypto.h"
#include "CryptoKeyType.h"
#include "rind.h"
#include <mutex>

struct KeyObjectData : ThreadSafeRefCounted<KeyObjectData> {
    WTF_MAKE_TZONE_ALLOCATED(KeyObjectData);

    KeyObjectData(WTF::Vector<uint8_t>&& symmetricKey)
        : symmetricKey(WTF::move(symmetricKey))
    {
    }

    KeyObjectData(ncrypto::EVPKeyPointer&& asymmetricKey)
        : asymmetricKey(WTF::move(asymmetricKey))
    {
    }

public:
    ~KeyObjectData() = default;

    static RefPtr<KeyObjectData> create(WTF::Vector<uint8_t>&& symmetricKey)
    {
        return adoptRef(*new KeyObjectData(WTF::move(symmetricKey)));
    }

    static RefPtr<KeyObjectData> create(ncrypto::EVPKeyPointer&& asymmetricKey)
    {
        return adoptRef(*new KeyObjectData(WTF::move(asymmetricKey)));
    }

    WTF::Vector<uint8_t> symmetricKey;
    const ncrypto::EVPKeyPointer asymmetricKey;

    // rind's copy of an Ed25519 private key, built on first use; null for any other key.
    const BunRindEd25519Key* rindEd25519Key() const
    {
        buildRindKey();
        return m_rindEd25519.get();
    }

    // rind's copy of a P-384 or P-521 private key, built on first use; null for any other key.
    const BunRindEcdsaKey* rindEcdsaKey() const
    {
        buildRindKey();
        return m_rindEcdsa.get();
    }

private:
    void buildRindKey() const
    {
        std::call_once(m_rindOnce, [this] {
            EVP_PKEY* key = asymmetricKey.get();
            if (!key)
                return;
            switch (EVP_PKEY_id(key)) {
            case EVP_PKEY_ED25519: {
                uint8_t seed[32];
                uint8_t publicKey[32];
                size_t seedLen = sizeof(seed);
                if (!EVP_PKEY_get_raw_private_key(key, seed, &seedLen) || seedLen != sizeof(seed)) {
                    ERR_clear_error();
                    return;
                }
                m_rindEd25519.reset(Bun__Rind__ed25519FromSeed(seed, publicKey));
                OPENSSL_cleanse(seed, sizeof(seed));
                break;
            }
            case EVP_PKEY_EC:
                m_rindEcdsa = Bun::Rind::ecdsaKey(EVP_PKEY_get0_EC_KEY(key));
                break;
            }
        });
    }

    mutable std::once_flag m_rindOnce;
    mutable Bun::Rind::Ed25519Key m_rindEd25519;
    mutable Bun::Rind::EcdsaKey m_rindEcdsa;
};
