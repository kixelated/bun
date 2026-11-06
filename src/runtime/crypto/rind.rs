//! Ed25519, X25519, and ECDSA and ECDH on P-256, P-384, and P-521 through
//! rind, for WebCrypto and `node:crypto` (`rind.h`). A `Key` is what rind
//! parsed, generated, or loaded from raw parts; C++ builds a BoringSSL key
//! from its raw parts only for the paths still on BoringSSL.

use core::slice;
use std::sync::OnceLock;

use rind::agreement;
use rind::digest;
use rind::signature::{self, EcdsaKeyPair, Ed25519KeyPair};

/// A pointer and length from C++, which may be null when empty.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    // SAFETY: the caller passes a readable span of `len` bytes.
    unsafe { slice::from_raw_parts(ptr, len) }
}

/// Copies `src` to C++'s buffer of `cap` bytes; its length, or 0 if it does
/// not fit.
unsafe fn write(src: &[u8], out: *mut u8, cap: usize) -> usize {
    if src.len() > cap {
        return 0;
    }
    // SAFETY: C++ passes a writable buffer of `cap` bytes.
    unsafe { slice::from_raw_parts_mut(out, src.len()) }.copy_from_slice(src);
    src.len()
}

/// `BunRindKind` in `rind.h`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Kind {
    Ed25519 = 0,
    X25519 = 1,
    P256 = 2,
    P384 = 3,
    P521 = 4,
}

impl Kind {
    const ALL: [Kind; 5] = [Kind::Ed25519, Kind::X25519, Kind::P256, Kind::P384, Kind::P521];

    /// The kind C++ names, or `None` for `BunRindKind::Any` and anything else.
    fn from_c(kind: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|k| *k as u8 == kind)
    }

    fn ecdsa(self) -> &'static signature::EcdsaSigningAlgorithm {
        match self {
            Kind::P256 => &signature::sign::ECDSA_P256_SHA256_FIXED,
            Kind::P384 => &signature::sign::ECDSA_P384_SHA384_FIXED,
            _ => &signature::sign::ECDSA_P521_SHA512_FIXED,
        }
    }

    fn verify(self) -> &'static signature::VerificationAlgorithm {
        match self {
            Kind::Ed25519 => &signature::verify::ED25519,
            Kind::P256 => &signature::verify::ECDSA_P256_SHA256_FIXED,
            Kind::P384 => &signature::verify::ECDSA_P384_SHA384_FIXED,
            _ => &signature::verify::ECDSA_P521_SHA512_FIXED,
        }
    }

    fn agreement(self) -> &'static agreement::Algorithm {
        match self {
            Kind::X25519 => &agreement::X25519,
            Kind::P256 => &agreement::ECDH_P256,
            Kind::P384 => &agreement::ECDH_P384,
            _ => &agreement::ECDH_P521,
        }
    }

    fn is_ec(self) -> bool {
        matches!(self, Kind::P256 | Kind::P384 | Kind::P521)
    }
}

/// `BunRindHash` in `rind.h`: the hashes rind signs and verifies ECDSA over.
fn hash_from_c(hash: u8) -> Option<&'static digest::Algorithm> {
    match hash {
        0 => Some(&digest::SHA256),
        1 => Some(&digest::SHA384),
        2 => Some(&digest::SHA512),
        _ => None,
    }
}

/// `BunRindFormat` in `rind.h`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Format {
    Pkcs8 = 0,
    Spki = 1,
    Sec1 = 2,
}

impl Format {
    fn from_c(format: u8) -> Option<Self> {
        match format {
            0 => Some(Format::Pkcs8),
            1 => Some(Format::Spki),
            2 => Some(Format::Sec1),
            _ => None,
        }
    }
}

enum Private {
    Ed25519(Ed25519KeyPair),
    X25519(agreement::PrivateKey),
    /// The same scalar for ECDSA and ECDH, as one BoringSSL `EC_KEY` serves both.
    Ec(EcdsaKeyPair, agreement::PrivateKey),
}

/// An asymmetric key: a private key with its public key, or a public key.
pub(crate) struct Key {
    kind: Kind,
    private: Option<Private>,
    /// The raw public key: 32 bytes, or a NIST curve's uncompressed point.
    public: agreement::PublicKey,
    /// Built on first verification: parsing an Ed25519 point costs more than
    /// BoringSSL's import, which defers that to verification too.
    verifier: OnceLock<Option<signature::PublicKey>>,
}

impl Key {
    fn new(kind: Kind, private: Option<Private>, public: &[u8]) -> Option<Box<Self>> {
        // Ed25519's raw public key is any 32 bytes until a signature is
        // checked against it, as BoringSSL holds it; X25519's parser takes
        // the same.
        let parse_as = match kind {
            Kind::Ed25519 => Kind::X25519,
            kind => kind,
        };
        let public = agreement::PublicKey::new(parse_as.agreement(), public).ok()?;
        Some(Box::new(Key {
            kind,
            private,
            public,
            verifier: OnceLock::new(),
        }))
    }

    fn ec(kind: Kind, key: EcdsaKeyPair) -> Option<Box<Self>> {
        let ecdh = agreement::PrivateKey::from_scalar(kind.agreement(), key.to_scalar().as_ref()).ok()?;
        let public = key.public_key();
        Self::new(kind, Some(Private::Ec(key, ecdh)), public.as_ref())
    }

    fn ed25519(key: Ed25519KeyPair) -> Option<Box<Self>> {
        let public = key.public_key();
        Self::new(Kind::Ed25519, Some(Private::Ed25519(key)), public.as_ref())
    }

    fn x25519(key: agreement::PrivateKey) -> Option<Box<Self>> {
        let public = key.public_key();
        Self::new(Kind::X25519, Some(Private::X25519(key)), public.as_ref())
    }

    fn generate(kind: Kind) -> Option<Box<Self>> {
        match kind {
            Kind::Ed25519 => Self::ed25519(Ed25519KeyPair::generate().ok()?),
            Kind::X25519 => Self::x25519(agreement::PrivateKey::generate(&agreement::X25519).ok()?),
            kind => Self::ec(kind, EcdsaKeyPair::generate(kind.ecdsa()).ok()?),
        }
    }

    /// Parses `der` as `kind`, and returns it only if it is the encoding
    /// this key writes back, which is what OpenSSL, BoringSSL, and Node
    /// write. Any other encoding of a valid key is BoringSSL's to parse, so
    /// that Bun takes and re-exports it exactly as before.
    fn parse(kind: Kind, format: Format, der: &[u8]) -> Option<Box<Self>> {
        let key = match (format, kind) {
            (Format::Pkcs8, Kind::Ed25519) => Self::ed25519(Ed25519KeyPair::from_pkcs8(der).ok()?),
            (Format::Pkcs8, Kind::X25519) => {
                Self::x25519(agreement::PrivateKey::from_pkcs8(&agreement::X25519, der).ok()?)
            }
            (Format::Pkcs8, kind) => Self::ec(kind, EcdsaKeyPair::from_pkcs8(kind.ecdsa(), der).ok()?),
            (Format::Sec1, kind) if kind.is_ec() => {
                Self::ec(kind, EcdsaKeyPair::from_sec1(kind.ecdsa(), der).ok()?)
            }
            (Format::Sec1, _) => return None,
            // Its one encoding, which BoringSSL takes without checking the point.
            (Format::Spki, Kind::Ed25519) => {
                let public = der.strip_prefix(&ED25519_SPKI_PREFIX)?;
                Self::new(Kind::Ed25519, None, public)
            }
            (Format::Spki, kind) => {
                let key = agreement::PublicKey::from_spki(kind.agreement(), der).ok()?;
                Self::new(kind, None, key.as_ref())
            }
        }?;
        let mut encoded = [0u8; MAX_ENCODED_LEN];
        let len = key.export(format, &mut encoded)?;
        (encoded[..len] == *der).then_some(key)
    }

    fn verifier(&self) -> Option<&signature::PublicKey> {
        self.verifier
            .get_or_init(|| signature::PublicKey::new(self.kind.verify(), self.public.as_ref()).ok())
            .as_ref()
    }

    /// Writes the key in `format` to `out`, returning its length.
    fn export(&self, format: Format, out: &mut [u8]) -> Option<usize> {
        let mut put = |src: &[u8]| {
            let dst = out.get_mut(..src.len())?;
            dst.copy_from_slice(src);
            Some(src.len())
        };
        match (format, &self.private) {
            (Format::Pkcs8, Some(Private::Ed25519(key))) => put(key.to_pkcs8v1().as_ref()),
            (Format::Pkcs8, Some(Private::X25519(key))) => put(key.to_pkcs8().as_ref()),
            (Format::Pkcs8, Some(Private::Ec(key, _))) => put(key.to_pkcs8().as_ref()),
            (Format::Sec1, Some(Private::Ec(key, _))) => put(key.to_sec1().as_ref()),
            (Format::Spki, _) if self.kind == Kind::Ed25519 => {
                let len = ED25519_SPKI_PREFIX.len();
                let dst = out.get_mut(..len + 32)?;
                dst[..len].copy_from_slice(&ED25519_SPKI_PREFIX);
                dst[len..].copy_from_slice(self.public.as_ref());
                Some(len + 32)
            }
            (Format::Spki, _) => put(self.public.to_spki().as_ref()),
            _ => None,
        }
    }
}

/// An Ed25519 SPKI (RFC 8410) before its 32-byte key.
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// The longest PKCS#8, SPKI, or SEC1 encoding of a key here: P-521's PKCS#8.
const MAX_ENCODED_LEN: usize = 256;

/// Generates a private key of `kind`; null if `kind` is unknown or the
/// random source failed.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__keyGenerate(kind: u8) -> Option<Box<Key>> {
    Key::generate(Kind::from_c(kind)?)
}

/// Parses `der` in `format` as `kind`, or as any kind for
/// `BunRindKind::Any`; null unless rind parses it and would write the same
/// bytes back.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__keyParse(
    kind: u8,
    format: u8,
    der: *const u8,
    der_len: usize,
) -> Option<Box<Key>> {
    let format = Format::from_c(format)?;
    // SAFETY: C++ passes the encoding's span.
    let der = unsafe { bytes(der, der_len) };
    match Kind::from_c(kind) {
        Some(kind) => Key::parse(kind, format, der),
        None => Kind::ALL.into_iter().find_map(|kind| Key::parse(kind, format, der)),
    }
}

/// Loads a public key from its raw bytes: 32 for Ed25519 and X25519, or an
/// X9.62 point, compressed or not, on the NIST curves; null if malformed or
/// off the curve.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__keyFromPublic(
    kind: u8,
    public: *const u8,
    public_len: usize,
) -> Option<Box<Key>> {
    // SAFETY: C++ passes the key's span.
    Key::new(Kind::from_c(kind)?, None, unsafe { bytes(public, public_len) })
}

/// Loads a private key from its raw bytes: Ed25519's seed, X25519's 32
/// bytes, or a NIST curve's big-endian scalar of the curve's size. A public
/// key, if given (`public_len` nonzero), must be the private key's; a NIST
/// curve's is required.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__keyFromPrivate(
    kind: u8,
    private: *const u8,
    private_len: usize,
    public: *const u8,
    public_len: usize,
) -> Option<Box<Key>> {
    let kind = Kind::from_c(kind)?;
    // SAFETY: C++ passes the private and the public key's spans.
    let (private, public) = unsafe { (bytes(private, private_len), bytes(public, public_len)) };
    let key = match kind {
        Kind::Ed25519 => Key::ed25519(Ed25519KeyPair::from_seed(private).ok()?),
        Kind::X25519 => Key::x25519(agreement::PrivateKey::from_scalar(&agreement::X25519, private).ok()?),
        kind => {
            return Key::ec(
                kind,
                EcdsaKeyPair::from_scalar_and_public_key(kind.ecdsa(), private, public).ok()?,
            );
        }
    }?;
    (public.is_empty() || key.public.as_ref() == public).then_some(key)
}

/// The public half of `key`, as its own key.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__keyPublicHalf(key: &Key) -> Box<Key> {
    Box::new(Key {
        kind: key.kind,
        private: None,
        public: key.public.clone(),
        verifier: OnceLock::new(),
    })
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__keyFree(key: Option<Box<Key>>) {
    drop(key);
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__keyKind(key: &Key) -> u8 {
    key.kind as u8
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__keyIsPrivate(key: &Key) -> bool {
    key.private.is_some()
}

/// Writes the raw public key, returning its length (0 if it does not fit).
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__keyPublic(key: &Key, out: *mut u8, cap: usize) -> usize {
    // SAFETY: C++ passes a writable buffer of `cap` bytes.
    unsafe { write(key.public.as_ref(), out, cap) }
}

/// Writes the raw private key: Ed25519's seed, X25519's 32 bytes, or a NIST
/// curve's scalar; its length, or 0 for a public key or a short buffer.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__keyPrivate(key: &Key, out: *mut u8, cap: usize) -> usize {
    // SAFETY: C++ passes a writable buffer of `cap` bytes.
    unsafe {
        match &key.private {
            Some(Private::Ed25519(key)) => write(key.to_seed().as_ref(), out, cap),
            Some(Private::X25519(key)) => write(key.to_scalar().as_ref(), out, cap),
            Some(Private::Ec(key, _)) => write(key.to_scalar().as_ref(), out, cap),
            None => 0,
        }
    }
}

/// Writes the key in `format` (`BunRindFormat`), returning its length; 0 if
/// the key has no such encoding (a public key's PKCS#8, an Ed25519 key's
/// SEC1) or it does not fit.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__keyExport(key: &Key, format: u8, out: *mut u8, cap: usize) -> usize {
    let Some(format) = Format::from_c(format) else {
        return 0;
    };
    let mut encoded = [0u8; MAX_ENCODED_LEN];
    match key.export(format, &mut encoded) {
        // SAFETY: C++ passes a writable buffer of `cap` bytes.
        Some(len) => unsafe { write(&encoded[..len], out, cap) },
        None => 0,
    }
}

/// Signs `message`: Ed25519 (`hash` ignored), or ECDSA over its `hash`
/// (`BunRindHash`) as r || s. Returns the signature's length, or 0 for a
/// public key, an unknown hash, or a short buffer.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__sign(
    key: &Key,
    hash: u8,
    message: *const u8,
    message_len: usize,
    out: *mut u8,
    cap: usize,
) -> usize {
    // SAFETY: C++ passes the message's span.
    let message = unsafe { bytes(message, message_len) };
    let signature = match &key.private {
        Some(Private::Ed25519(key)) => key.sign(message),
        Some(Private::Ec(key, _)) => {
            let Some(hash) = hash_from_c(hash) else {
                return 0;
            };
            match key.sign_digest(&digest::digest(hash, message)) {
                Ok(signature) => signature,
                Err(_) => return 0,
            }
        }
        _ => return 0,
    };
    // SAFETY: C++ passes a writable buffer of `cap` bytes.
    unsafe { write(signature.as_ref(), out, cap) }
}

/// Whether `signature` verifies over `message`: Ed25519 (`hash` ignored), or
/// ECDSA r || s over its `hash`. False for a malformed key or signature.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__verify(
    key: &Key,
    hash: u8,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> bool {
    let Some(verifier) = key.verifier() else {
        return false;
    };
    // SAFETY: C++ passes the message's and the signature's spans.
    let (message, signature) = unsafe { (bytes(message, message_len), bytes(signature, signature_len)) };
    if key.kind == Kind::Ed25519 {
        return verifier.verify(message, signature).is_ok();
    }
    match hash_from_c(hash) {
        Some(hash) => verifier.verify_digest(&digest::digest(hash, message), signature).is_ok(),
        None => false,
    }
}

/// A hash being streamed, for node's `Sign` and `Verify`.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__digestNew(hash: u8) -> Option<Box<digest::Context>> {
    Some(Box::new(digest::Context::new(hash_from_c(hash)?)))
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__digestUpdate(context: &mut digest::Context, data: *const u8, len: usize) {
    // SAFETY: C++ passes the data's span.
    context.update(unsafe { bytes(data, len) });
}

/// Finishes the hash, and frees its context.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__digestFinish(mut context: Box<digest::Context>) -> Box<digest::Digest> {
    Box::new(context.finish())
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__digestContextFree(context: Option<Box<digest::Context>>) {
    drop(context);
}

/// Writes the digest's bytes, at most 64, returning their length.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__digestBytes(digest: &digest::Digest, out: &mut [u8; 64]) -> usize {
    let bytes = digest.as_ref();
    out[..bytes.len()].copy_from_slice(bytes);
    bytes.len()
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__digestFree(digest: Option<Box<digest::Digest>>) {
    drop(digest);
}

/// Signs `digest` with an ECDSA private key, as r || s; its length, or 0.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__signDigest(
    key: &Key,
    digest: &digest::Digest,
    out: *mut u8,
    cap: usize,
) -> usize {
    let Some(Private::Ec(key, _)) = &key.private else {
        return 0;
    };
    match key.sign_digest(digest) {
        // SAFETY: C++ passes a writable buffer of `cap` bytes.
        Ok(signature) => unsafe { write(signature.as_ref(), out, cap) },
        Err(_) => 0,
    }
}

/// Whether an ECDSA r || s `signature` verifies over `digest`.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__verifyDigest(
    key: &Key,
    digest: &digest::Digest,
    signature: *const u8,
    signature_len: usize,
) -> bool {
    if !key.kind.is_ec() {
        return false;
    }
    let Some(verifier) = key.verifier() else {
        return false;
    };
    // SAFETY: C++ passes the signature's span.
    verifier
        .verify_digest(digest, unsafe { bytes(signature, signature_len) })
        .is_ok()
}

/// Agrees with the peer's raw public key (a NIST curve's compressed or
/// uncompressed point), writing the shared secret; its length, or 0 if the
/// peer's key is malformed, off the curve, or gives X25519's all-zero
/// output.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__agree(
    key: &Key,
    peer: *const u8,
    peer_len: usize,
    out: *mut u8,
    cap: usize,
) -> usize {
    let private = match &key.private {
        Some(Private::X25519(key)) => key,
        Some(Private::Ec(_, key)) => key,
        _ => return 0,
    };
    // SAFETY: C++ passes the peer key's span.
    let Ok(peer) = agreement::PublicKey::new(key.kind.agreement(), unsafe { bytes(peer, peer_len) }) else {
        return 0;
    };
    match private.agree(peer.as_ref()) {
        // SAFETY: C++ passes a writable buffer of `cap` bytes.
        Ok(secret) => unsafe { write(secret.as_ref(), out, cap) },
        Err(_) => 0,
    }
}

/// X25519 with a raw private key, which needs no public key; false for
/// the all-zero output.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__x25519(private: &[u8; 32], peer: &[u8; 32], out: &mut [u8; 32]) -> bool {
    let Ok(key) = agreement::PrivateKey::from_scalar(&agreement::X25519, private) else {
        return false;
    };
    match key.agree(peer) {
        Ok(secret) => {
            out.copy_from_slice(secret.as_ref());
            true
        }
        Err(_) => false,
    }
}
