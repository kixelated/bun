// Asymmetric crypto end to end, WebCrypto and node:crypto: microseconds per call, median of
// ROUNDS batches. `bun bench/crypto/asymmetric-sign-verify.mjs [filter]`.
import crypto from "node:crypto";
const { subtle } = globalThis.crypto;
const BUDGET = Number(process.env.BUDGET_MS ?? 400);
const ROUNDS = Number(process.env.ROUNDS ?? 5);
const only = process.argv[2] ?? "";

async function time(name, fn) {
  if (only && !name.toLowerCase().includes(only.toLowerCase())) return;
  const warm = performance.now();
  let n = 0;
  while (performance.now() - warm < BUDGET / 4) { await fn(); n++; }
  const batch = Math.max(1, Math.floor(n * 2));
  const samples = [];
  for (let r = 0; r < ROUNDS; r++) {
    const t = performance.now();
    for (let i = 0; i < batch; i++) await fn();
    samples.push(((performance.now() - t) * 1000) / batch);
  }
  samples.sort((a, b) => a - b);
  console.log(`${name}\t${samples[ROUNDS >> 1].toFixed(2)}`);
}

const msg = new Uint8Array(64).fill(0x5a);

// WebCrypto
{
  const ed = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const edSig = await subtle.sign({ name: "Ed25519" }, ed.privateKey, msg);
  const edPkcs8 = await subtle.exportKey("pkcs8", ed.privateKey);
  await time("webcrypto Ed25519 generateKey", () => subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]));
  await time("webcrypto Ed25519 importKey pkcs8", () => subtle.importKey("pkcs8", edPkcs8, { name: "Ed25519" }, true, ["sign"]));
  await time("webcrypto Ed25519 sign", () => subtle.sign({ name: "Ed25519" }, ed.privateKey, msg));
  await time("webcrypto Ed25519 verify", () => subtle.verify({ name: "Ed25519" }, ed.publicKey, edSig, msg));

  for (const [curve, hash] of [["P-256", "SHA-256"], ["P-384", "SHA-384"], ["P-521", "SHA-512"]]) {
    const alg = { name: "ECDSA", namedCurve: curve };
    const k = await subtle.generateKey(alg, true, ["sign", "verify"]);
    const pkcs8 = await subtle.exportKey("pkcs8", k.privateKey);
    const sig = await subtle.sign({ name: "ECDSA", hash }, k.privateKey, msg);
    await time(`webcrypto ECDSA ${curve} generateKey`, () => subtle.generateKey(alg, true, ["sign", "verify"]));
    await time(`webcrypto ECDSA ${curve} importKey pkcs8`, () => subtle.importKey("pkcs8", pkcs8, alg, true, ["sign"]));
    await time(`webcrypto ECDSA ${curve} importKey pkcs8 + one sign ${hash}`, async () => subtle.sign({ name: "ECDSA", hash }, await subtle.importKey("pkcs8", pkcs8, alg, true, ["sign"]), msg));
    await time(`webcrypto ECDSA ${curve} sign ${hash}`, () => subtle.sign({ name: "ECDSA", hash }, k.privateKey, msg));
    await time(`webcrypto ECDSA ${curve} verify ${hash}`, () => subtle.verify({ name: "ECDSA", hash }, k.publicKey, sig, msg));
    if (curve !== "P-256") {
      const sig256 = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k.privateKey, msg);
      await time(`webcrypto ECDSA ${curve} sign SHA-256 (control)`, () => subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k.privateKey, msg));
      await time(`webcrypto ECDSA ${curve} verify SHA-256 (control)`, () => subtle.verify({ name: "ECDSA", hash: "SHA-256" }, k.publicKey, sig256, msg));
    }
    const ecdh = { name: "ECDH", namedCurve: curve };
    const a = await subtle.generateKey(ecdh, true, ["deriveBits"]);
    const b = await subtle.generateKey(ecdh, true, ["deriveBits"]);
    await time(`webcrypto ECDH ${curve} generateKey`, () => subtle.generateKey(ecdh, true, ["deriveBits"]));
    await time(`webcrypto ECDH ${curve} deriveBits (control)`, () => subtle.deriveBits({ name: "ECDH", public: b.publicKey }, a.privateKey, null));
  }
  const xa = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const xb = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  await time("webcrypto X25519 generateKey (control)", () => subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]));
  await time("webcrypto X25519 deriveBits (control)", () => subtle.deriveBits({ name: "X25519", public: xb.publicKey }, xa.privateKey, 256));
}

// node:crypto, with KeyObjects made once.
{
  const ed = crypto.generateKeyPairSync("ed25519");
  const edSig = crypto.sign(null, msg, ed.privateKey);
  await time("node Ed25519 sign", () => crypto.sign(null, msg, ed.privateKey));
  await time("node Ed25519 verify", () => crypto.verify(null, msg, ed.publicKey, edSig));
  const edPem = ed.privateKey.export({ type: "pkcs8", format: "pem" });
  await time("node Ed25519 sign, PEM key each call", () => crypto.sign(null, msg, edPem));
  await time("node Ed25519 generateKeyPairSync (control)", () => crypto.generateKeyPairSync("ed25519"));
  for (const [curve, hash] of [["P-256", "sha256"], ["P-384", "sha384"], ["P-521", "sha512"]]) {
    const k = crypto.generateKeyPairSync("ec", { namedCurve: curve });
    const der = crypto.sign(hash, msg, k.privateKey);
    const p1363 = crypto.sign(hash, msg, { key: k.privateKey, dsaEncoding: "ieee-p1363" });
    await time(`node ECDSA ${curve} sign ${hash}`, () => crypto.sign(hash, msg, k.privateKey));
    await time(`node ECDSA ${curve} sign ${hash} ieee-p1363`, () => crypto.sign(hash, msg, { key: k.privateKey, dsaEncoding: "ieee-p1363" }));
    await time(`node ECDSA ${curve} verify ${hash}`, () => crypto.verify(hash, msg, k.publicKey, der));
    await time(`node ECDSA ${curve} verify ${hash} ieee-p1363`, () => crypto.verify(hash, msg, { key: k.publicKey, dsaEncoding: "ieee-p1363" }, p1363));
    const pem = k.privateKey.export({ type: "pkcs8", format: "pem" });
    await time(`node ECDSA ${curve} sign ${hash}, PEM key each call`, () => crypto.sign(hash, msg, pem));
    await time(`node ECDSA ${curve} generateKeyPairSync`, () => crypto.generateKeyPairSync("ec", { namedCurve: curve }));
  }
}
