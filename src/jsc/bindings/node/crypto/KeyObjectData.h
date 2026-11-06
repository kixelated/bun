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
        : m_asymmetricKey(WTF::move(asymmetricKey))
        , m_rindKind(Bun::Rind::kindOf(m_asymmetricKey.get()))
    {
    }

    KeyObjectData(Bun::Rind::Key&& rindKey)
        : m_rindKind(Bun__Rind__keyKind(rindKey.get()))
        , m_fromRind(true)
        , m_rindKey(WTF::move(rindKey))
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

    static RefPtr<KeyObjectData> create(Bun::Rind::Key&& rindKey)
    {
        return adoptRef(*new KeyObjectData(WTF::move(rindKey)));
    }

    WTF::Vector<uint8_t> symmetricKey;

    // BoringSSL's copy of an asymmetric key, built on first use from rind's for the paths still on BoringSSL.
    const ncrypto::EVPKeyPointer& asymmetricKey() const
    {
        if (m_fromRind) {
            std::call_once(m_asymmetricOnce, [this] {
                m_asymmetricKey = Bun::Rind::toEVP(*m_rindKey, Bun__Rind__keyIsPrivate(m_rindKey.get()));
            });
        }
        return m_asymmetricKey;
    }

    // Whether rind parsed or generated the key, so it holds the key's raw parts without BoringSSL.
    bool fromRind() const { return m_fromRind; }

    // The kind of an asymmetric key rind runs, known without building either copy.
    std::optional<BunRindKind> rindKind() const { return m_rindKind; }

    // rind's copy of a key of a kind it runs; loaded on first use from BoringSSL's when BoringSSL parsed it.
    const BunRindKey* rindKey() const
    {
        if (!m_rindKind)
            return nullptr;
        std::call_once(m_rindOnce, [this] {
            if (!m_fromRind)
                m_rindKey = Bun::Rind::fromEVP(m_asymmetricKey.get(), true);
        });
        return m_rindKey.get();
    }

private:
    mutable std::once_flag m_asymmetricOnce;
    mutable ncrypto::EVPKeyPointer m_asymmetricKey;
    std::optional<BunRindKind> m_rindKind;
    const bool m_fromRind { false };
    mutable std::once_flag m_rindOnce;
    mutable Bun::Rind::Key m_rindKey;
};
