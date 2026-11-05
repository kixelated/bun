//! Ed25519, and ECDSA on P-384 and P-521, through rind, for WebCrypto and
//! `node:crypto` (`rind.h`). BoringSSL keeps everything else, including
//! these keys' import and export: a key here is built from the raw key
//! BoringSSL parsed, and its C++ owner caches it.

use core::slice;

use rind::signature::{self, EcdsaKeyPair, Ed25519KeyPair, PublicKey};

/// A pointer and length from C++, which may be null when empty.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    // SAFETY: the caller passes a readable span of `len` bytes.
    unsafe { slice::from_raw_parts(ptr, len) }
}

/// Builds the key pair for a 32-byte seed and writes its public key.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__ed25519FromSeed(
    seed: &[u8; 32],
    out_public: &mut [u8; 32],
) -> Option<Box<Ed25519KeyPair>> {
    let pkcs8 = ed25519_pkcs8_v1(seed);
    let key = Ed25519KeyPair::from_pkcs8(&pkcs8).ok()?;
    out_public.copy_from_slice(key.public_key().as_ref());
    Some(Box::new(key))
}

/// rind loads a seed alone only from PKCS#8 v1 (RFC 8410), which carries no
/// public key to check it against.
fn ed25519_pkcs8_v1(seed: &[u8; 32]) -> [u8; 48] {
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut der = [0u8; 48];
    der[..16].copy_from_slice(&PREFIX);
    der[16..].copy_from_slice(seed);
    der
}

/// Generates a key pair and writes its seed and public key.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__ed25519Generate(
    out_seed: &mut [u8; 32],
    out_public: &mut [u8; 32],
) -> Option<Box<Ed25519KeyPair>> {
    let key = Ed25519KeyPair::generate().ok()?;
    out_seed.copy_from_slice(key.to_seed().as_ref());
    out_public.copy_from_slice(key.public_key().as_ref());
    Some(Box::new(key))
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__ed25519Sign(
    key: &Ed25519KeyPair,
    message: *const u8,
    message_len: usize,
    out_signature: &mut [u8; 64],
) {
    // SAFETY: C++ passes the message's span.
    let signature = key.sign(unsafe { bytes(message, message_len) });
    out_signature.copy_from_slice(signature.as_ref());
}

/// Whether `signature` verifies over the message; false for a malformed or
/// small-order public key.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__ed25519Verify(
    public_key: &[u8; 32],
    message: *const u8,
    message_len: usize,
    signature: &[u8; 64],
) -> bool {
    let Ok(key) = PublicKey::new(&signature::verify::ED25519, public_key) else {
        return false;
    };
    // SAFETY: C++ passes the message's span.
    key.verify(unsafe { bytes(message, message_len) }, signature)
        .is_ok()
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__ed25519Free(key: Option<Box<Ed25519KeyPair>>) {
    drop(key);
}

/// `BunRindCurve` in `rind.h`. Each curve signs with the hash of its size,
/// and the signature is `r || s`, each the curve's size (IEEE P1363).
#[derive(Clone, Copy)]
enum Curve {
    P384,
    P521,
}

impl Curve {
    /// The curve C++ names, which crosses as its `uint8_t`.
    fn from_c(curve: u8) -> Option<Self> {
        match curve {
            0 => Some(Curve::P384),
            1 => Some(Curve::P521),
            _ => None,
        }
    }

    fn sign(self) -> &'static signature::EcdsaSigningAlgorithm {
        match self {
            Curve::P384 => &signature::sign::ECDSA_P384_SHA384_FIXED,
            Curve::P521 => &signature::sign::ECDSA_P521_SHA512_FIXED,
        }
    }

    fn verify(self) -> &'static signature::VerificationAlgorithm {
        match self {
            Curve::P384 => &signature::verify::ECDSA_P384_SHA384_FIXED,
            Curve::P521 => &signature::verify::ECDSA_P521_SHA512_FIXED,
        }
    }

    fn scalar_len(self) -> usize {
        match self {
            Curve::P384 => 48,
            Curve::P521 => 66,
        }
    }
}

/// Builds the key pair for a big-endian scalar of the curve's size,
/// refused unless `point`, an X9.62 uncompressed point, is its public key.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__ecdsaFromScalar(
    curve: u8,
    scalar: *const u8,
    scalar_len: usize,
    point: *const u8,
    point_len: usize,
) -> Option<Box<EcdsaKeyPair>> {
    let curve = Curve::from_c(curve)?;
    // SAFETY: C++ passes the scalar's and the point's spans.
    let (scalar, point) = unsafe { (bytes(scalar, scalar_len), bytes(point, point_len)) };
    EcdsaKeyPair::from_private_key_and_public_key(curve.sign(), scalar, point)
        .ok()
        .map(Box::new)
}

/// Generates a key pair and writes its scalar, the curve's size, and its
/// X9.62 uncompressed point, `1 + 2 *` the curve's size.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__ecdsaGenerate(
    curve: u8,
    out_scalar: *mut u8,
    out_point: *mut u8,
) -> Option<Box<EcdsaKeyPair>> {
    let curve = Curve::from_c(curve)?;
    let key = EcdsaKeyPair::generate(curve.sign()).ok()?;
    let len = curve.scalar_len();
    // SAFETY: C++ passes buffers of the sizes documented above.
    let (scalar, point) = unsafe {
        (
            slice::from_raw_parts_mut(out_scalar, len),
            slice::from_raw_parts_mut(out_point, 1 + 2 * len),
        )
    };
    scalar.copy_from_slice(key.to_scalar().as_ref());
    point.copy_from_slice(key.public_key().as_ref());
    Some(Box::new(key))
}

/// Signs the message and writes `r || s`, twice the curve's size; false if
/// signing failed.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__ecdsaSign(
    key: &EcdsaKeyPair,
    message: *const u8,
    message_len: usize,
    out_signature: *mut u8,
    out_signature_len: usize,
) -> bool {
    // SAFETY: C++ passes the message's span.
    let Ok(signature) = key.sign(unsafe { bytes(message, message_len) }) else {
        return false;
    };
    if signature.as_ref().len() != out_signature_len {
        return false;
    }
    // SAFETY: C++ passes a writable buffer of `out_signature_len` bytes.
    unsafe { slice::from_raw_parts_mut(out_signature, out_signature_len) }
        .copy_from_slice(signature.as_ref());
    true
}

/// Whether `r || s` verifies over the message for the X9.62 uncompressed
/// point; false for a malformed point or signature.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__ecdsaVerify(
    curve: u8,
    point: *const u8,
    point_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> bool {
    let Some(curve) = Curve::from_c(curve) else {
        return false;
    };
    // SAFETY: C++ passes the point's, the message's, and the signature's spans.
    let (point, message, signature) = unsafe {
        (
            bytes(point, point_len),
            bytes(message, message_len),
            bytes(signature, signature_len),
        )
    };
    let Ok(key) = PublicKey::new(curve.verify(), point) else {
        return false;
    };
    key.verify(message, signature).is_ok()
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn Bun__Rind__ecdsaFree(key: Option<Box<EcdsaKeyPair>>) {
    drop(key);
}
