#include "CryptoGenNidKeyPair.h"
#include "CryptoUtil.h"
#include "NodeValidator.h"
#include "ErrorCode.h"
#include "rind.h"

using namespace Bun;
using namespace JSC;

extern "C" void Bun__NidKeyPairJobCtx__deinit(NidKeyPairJobCtx* ctx)
{
    ctx->deinit();
}

void NidKeyPairJobCtx::deinit()
{
    delete this;
}

extern "C" void Bun__NidKeyPairJobCtx__runTask(NidKeyPairJobCtx* ctx, JSGlobalObject* globalObject)
{
    if (ctx->generateOnRind())
        return;
    ncrypto::EVPKeyCtxPointer keyCtx = ctx->setup();
    if (!keyCtx) {
        return;
    }
    ctx->runTask(globalObject, keyCtx);
}

extern "C" void Bun__NidKeyPairJobCtx__runFromJS(NidKeyPairJobCtx* ctx, JSGlobalObject* globalObject, JSCallbackArgs* out)
{
    *out = ctx->runFromJS(globalObject);
}

extern "C" void Bun__NidKeyPairJob__createAndSchedule(JSGlobalObject* globalObject, NidKeyPairJobCtx* ctx, EncodedJSValue callback);
void NidKeyPairJob::createAndSchedule(JSGlobalObject* globalObject, NidKeyPairJobCtx&& ctx, JSValue callback)
{
    NidKeyPairJobCtx* ctxCopy = new NidKeyPairJobCtx(WTF::move(ctx));
    Bun__NidKeyPairJob__createAndSchedule(globalObject, ctxCopy, JSValue::encode(callback));
}

// Generates an Ed25519 or X25519 key on rind. Returns false to leave every other type to BoringSSL.
bool NidKeyPairJobCtx::generateOnRind()
{
    if (m_id != EVP_PKEY_ED25519 && m_id != EVP_PKEY_X25519)
        return false;
    auto key = Bun::Rind::adopt(Bun__Rind__keyGenerate(m_id == EVP_PKEY_ED25519 ? BunRindKind::Ed25519 : BunRindKind::X25519));
    if (key)
        m_keyObj = KeyObject::create(CryptoKeyType::Private, KeyObjectData::create(WTF::move(key)));
    return true;
}

ncrypto::EVPKeyCtxPointer NidKeyPairJobCtx::setup()
{
    ncrypto::EVPKeyCtxPointer ctx = ncrypto::EVPKeyCtxPointer::NewFromID(m_id);
    if (!ctx.initForKeygen()) {
        m_opensslError = ERR_get_error();
        return {};
    }
    return ctx;
}

std::optional<NidKeyPairJobCtx> NidKeyPairJobCtx::fromJS(JSGlobalObject* globalObject, ThrowScope& scope, const GCOwnedDataScope<WTF::StringView>& typeView, JSValue optionsValue, const KeyEncodingConfig& config)
{
    int id;
    if (typeView == "ed25519"_s) {
        id = EVP_PKEY_ED25519;
    } else if (typeView == "ed448"_s) {
        id = EVP_PKEY_ED448;
    } else if (typeView == "x25519"_s) {
        id = EVP_PKEY_X25519;
    } else if (typeView == "x448"_s) {
        id = EVP_PKEY_X448;
    } else if (int pqcNid = pqcKeyTypeToNid(typeView)) {
        id = pqcNid;
    } else {
        UNREACHABLE();
    }

    return NidKeyPairJobCtx(
        id,
        config);
}
