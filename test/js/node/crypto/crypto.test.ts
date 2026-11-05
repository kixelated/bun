import { CryptoHasher, MD4, MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SHA512_256, gc } from "bun";
import { describe, expect, it } from "bun:test";
import crypto from "crypto";
import { bunEnv, bunExe, isWindows, tmpdirSync } from "harness";
import path from "path";
import { readKey } from "../test/common/fixtures";
import { hashesFixture } from "./fixtures/sign.fixture.ts";
const HashClasses = [MD5, MD4, SHA1, SHA224, SHA256, SHA384, SHA512, SHA512_256];

describe("CryptoHasher", () => {
  it("CryptoHasher.algorithms", () => {
    expect(CryptoHasher.algorithms).toEqual([
      "blake2b256",
      "blake2b512",
      "blake2s256",
      "md4",
      "md5",
      "ripemd160",
      "sha1",
      "sha224",
      "sha256",
      "sha384",
      "sha512",
      "sha512-224",
      "sha512-256",
      "sha3-224",
      "sha3-256",
      "sha3-384",
      "sha3-512",
      "shake128",
      "shake256",
    ]);
  });

  // prettier-ignore
  const expected = {
    blake2b256: "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610",
    blake2b512: "021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0",
    blake2s256: "9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b",
    md4: "aa010fbc1d14c795d86ef98c95479d17",
    md5: "5eb63bbbe01eeed093cb22bb8f5acdc3",
    ripemd160: "98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f",
    sha1: "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
    sha224: "2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b",
    sha256: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    sha384: "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd",
    sha512: "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f",
    "sha512-224": "22e0d52336f64a998085078b05a6e37b26f8120f43bf4db4c43a64ee",
    "sha512-256": "0ac561fac838104e3f2e4ad107b4bee3e938bf15f2b15f009ccccd61a913f017",
    "sha3-224": "dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5",
    "sha3-256": "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938",
    "sha3-384": "83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b",
    "sha3-512": "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a",
    shake128: "3a9159f071e4dd1c8c4f968607c30942",
    shake256: "369771bb2cb9d2b04c1d54cca487e372d9f187f73f7ba3f65b95c8ee7798c527",
  } as const;

  const expectedBitLength = {
    blake2b256: 256,
    blake2b512: 512,
    blake2s256: 256,
    md4: 128,
    md5: 128,
    ripemd160: 160,
    sha1: 160,
    sha224: 224,
    sha256: 256,
    sha384: 384,
    sha512: 512,
    "sha512-224": 224,
    "sha512-256": 256,
    "sha3-224": 224,
    "sha3-256": 256,
    "sha3-384": 384,
    "sha3-512": 512,
    shake128: 128,
    shake256: 256,
  } as const;

  for (const algorithm of CryptoHasher.algorithms) {
    it(`new CryptoHasher ${algorithm}`, () => {
      var hasher = new CryptoHasher(algorithm);
      expect(hasher.algorithm).toEqual(algorithm);
      expect(hasher.byteLength).toEqual(expectedBitLength[algorithm] / 8);
      hasher.update("hello world");
      expect(hasher.digest("hex")).toEqual(expected[algorithm]);
    });

    it(`CryptoHasher.hash ${algorithm}`, () => {
      expect(CryptoHasher.hash(algorithm, "hello world").toString("hex")).toEqual(expected[algorithm]);
    });

    it(`new CryptoHasher ${algorithm} multi-part`, () => {
      var hasher = new CryptoHasher(algorithm);
      hasher.update("hello ");
      hasher.update("world");
      expect(hasher.digest("hex")).toBe(expected[algorithm]);
      expect(hasher.algorithm).toBe(algorithm);
    });

    it(`new CryptoHasher ${algorithm} to Buffer`, () => {
      var hasher = new CryptoHasher(algorithm);
      expect(hasher.algorithm).toEqual(algorithm);
      hasher.update("hello world");
      expect(hasher.digest()).toEqual(Buffer.from(expected[algorithm], "hex"));
    });
  }

  it("CryptoHasher resets when digest is called", () => {
    var hasher = new CryptoHasher("sha256");
    hasher.update("hello");
    expect(hasher.digest("hex")).toBe("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    hasher.update("world");
    expect(hasher.digest("hex")).toBe("486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7");
  });

  for (let alg of CryptoHasher.algorithms) {
    it(`CryptoHasher ${alg} copy is the same`, () => {
      const orig = new CryptoHasher(alg);
      orig.update("hello");
      const copy = orig.copy();

      expect(copy.digest("hex")).toBe(orig.digest("hex"));
      expect(copy.algorithm).toBe(orig.algorithm);
    });

    it(`CryptoHasher ${alg} copy is not linked`, () => {
      const orig = new CryptoHasher(alg);
      orig.update("hello");
      const copy = orig.copy();

      orig.update("world");
      expect(copy.digest("hex")).not.toBe(orig.digest("hex"));
    });

    it(`CryptoHasher ${alg} copy can be used after digest()`, () => {
      const orig = new CryptoHasher(alg);
      orig.update("hello");
      orig.digest("hex");
      const copy = orig.copy();

      expect(() => copy.digest("hex")).not.toThrow();
    });

    it(`CryptoHasher ${alg} copy updates the same`, () => {
      const orig = new CryptoHasher(alg);
      orig.update("hello");
      const copy = orig.copy();

      orig.update("world");
      copy.update("world");
      expect(copy.digest("hex")).toBe(orig.digest("hex"));
    });
  }
});

describe("createHash outputLength", () => {
  it("shake128 digest matches Node.js for small and zero outputLength", () => {
    expect(crypto.createHash("shake128", { outputLength: 8 }).update("abc").digest("hex")).toBe("5881092dd818bf5c");
    expect(crypto.createHash("shake128", { outputLength: 32 }).update("abc").digest("hex")).toBe(
      "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
    );
    expect(crypto.createHash("shake128", { outputLength: 0 }).update("abc").digest("hex")).toBe("");
    expect(crypto.createHash("shake128", { outputLength: 0 }).update("abc").digest()).toEqual(Buffer.alloc(0));
    expect(
      crypto.createHash("shake128", { outputLength: 8 }).update("abc").copy({ outputLength: 4 }).digest("hex"),
    ).toBe("5881092d");
  });

  it.skipIf(isWindows)("shake128 outputLength >= 2**31 does not abort the process", async () => {
    // options.outputLength is validated against the full uint32 range, so 2**31
    // must either produce a digest or throw a catchable error, never terminate
    // the process.
    const messages: string[] = [];
    const entering = Promise.withResolvers<void>();
    const done = Promise.withResolvers<void>();
    await using proc = Bun.spawn({
      cmd: [
        bunExe(),
        "-e",
        `const crypto = require("node:crypto");
         const known = "5881092dd818bf5cf8a3ddb793fbcba7";
         const h = crypto.createHash("shake128", { outputLength: 2 ** 31 }).update("abc");
         process.send("entering");
         try {
           const d = h.digest();
           if (d.length !== 2 ** 31) throw new Error("wrong length " + d.length);
           if (d.subarray(0, 16).toString("hex") !== known) throw new Error("wrong prefix");
           process.send("ok");
         } catch (e) {
           process.send("caught:" + (e.code || e.name));
         }`,
      ],
      env: bunEnv,
      stdout: "ignore",
      stderr: "ignore",
      ipc(message) {
        messages.push(String(message));
        if (message === "entering") entering.resolve();
        else done.resolve();
      },
      serialization: "json",
    });

    // The abort is a synchronous capacity check that fires instantly; past it
    // the child squeezes 2 GiB of output, which is too slow in debug to await.
    // Give it a short window after reaching the call site, then stop it.
    await Promise.race([entering.promise, proc.exited]);
    await Promise.race([done.promise, proc.exited, Bun.sleep(2000)]);
    proc.kill("SIGKILL");

    const exitCode = await proc.exited;

    expect(messages[0]).toBe("entering");
    expect(proc.signalCode).not.toBe("SIGABRT");
    if (proc.signalCode === null) {
      expect(messages[1]).toMatch(/^(ok|caught:\S+)$/);
      expect(exitCode).toBe(0);
    } else {
      expect(proc.signalCode).toBe("SIGKILL");
    }
  });
});

describe("crypto.getCurves", () => {
  it("should return an array of strings", () => {
    expect(Array.isArray(crypto.getCurves())).toBe(true);
    expect(typeof crypto.getCurves()[0]).toBe("string");
  });

  it("is sorted", () => {
    expect(crypto.getCurves()).toEqual(crypto.getCurves().toSorted());
  });
});

describe("crypto.getCipherInfo", () => {
  it.each([
    ["aes-128-cbc", { mode: "cbc", name: "aes-128-cbc", nid: 419, keyLength: 16, blockSize: 16, ivLength: 16 }],
    ["aes-128-ecb", { mode: "ecb", name: "aes-128-ecb", nid: 418, keyLength: 16, blockSize: 16, ivLength: undefined }],
    ["rc4", { mode: "stream", name: "rc4", nid: 5, keyLength: 16, blockSize: undefined, ivLength: undefined }],
  ])("of %s has the properties of Node's, in their order", (name, expected) => {
    const info = crypto.getCipherInfo(name)!;
    expect(Object.entries(info)).toEqual(Object.entries(expected));
    expect(Object.getPrototypeOf(info)).toBeNull();
  });
});

it("crypto.getRandomValues has its name", () => {
  expect(crypto.getRandomValues.name).toBe("getRandomValues");
  expect(crypto.getRandomValues).toHaveLength(1);
});

describe("names of digests", () => {
  const rsaKey = readKey("rsa_private.pem", "ascii");
  // Every function that takes the name of a digest. The last two are for digests that RSA signs with.
  const functions: [string, (name: string) => unknown][] = [
    ["createHash", name => crypto.createHash(name).update("x").digest("hex")],
    ["hash", name => crypto.hash(name, "x")],
    ["createHmac", name => crypto.createHmac(name, "key").update("x").digest("hex")],
    ["pbkdf2Sync", name => crypto.pbkdf2Sync("password", "salt", 1, 8, name).toString("hex")],
    ["hkdfSync", name => Buffer.from(crypto.hkdfSync(name, "key", "salt", "info", 8)).toString("hex")],
    ["sign", name => crypto.sign(name, Buffer.from("x"), rsaKey).toString("hex")],
    ["createSign", name => crypto.createSign(name).update("x").sign(rsaKey, "hex")],
  ];

  describe.each([
    ["sha256", ["Sha256", "RSA-SHA256", "rsa-sha256", "sha2-256", "SHA-256", "sha256withrsaencryption"]],
    ["sha1", ["Sha1", "RSA-SHA1-2", "ssl3-sha1", "SHA1WITHRSAENCRYPTION"]],
    ["md5", ["RSA-MD5", "rsa-md5", "ssl3-md5", "Md5WithRsaEncryption"]],
    ["ripemd160", ["Ripemd160", "ripemd", "ripemd-160", "rmd160", "RMD160", "RSA-RIPEMD160", "ripemd160WithRSA"]],
    ["sha512-256", ["Sha512-256", "sha2-512/256", "RSA-SHA512/256", "sha512-256WithRSAEncryption"]],
    ["sha3-256", ["Sha3-256", "RSA-SHA3-256", "id-rsassa-pkcs1-v1_5-with-sha3-256"]],
    ["md5-sha1", ["MD5-SHA1", "Md5-Sha1"]],
  ])("of %s", (canonical, aliases) => {
    it.each(functions)("in %s()", (_, call) => {
      const expected = call(canonical);
      expect(aliases.map(alias => [alias, call(alias)])).toEqual(aliases.map(alias => [alias, expected]));
    });
  });

  it("of blake2b512, which HMAC takes too", () => {
    for (const name of ["blake2b512", "BLAKE2b512", "blake2b-512"]) {
      expect(crypto.createHmac(name, "k").update("x").digest("hex")).toBe(
        "3d24b96bcbfb1458d029341f06c1be7861e8cc0408e507413ba4a59d74119164190d22eceb5060c276c23328ac181ddecde3d0c1a31d7d8ba81b59aaeae9e21e",
      );
      expect(Buffer.from(crypto.hkdfSync(name, "k", "s", "i", 16)).toString("hex")).toBe(
        "ba92a70abe7a73fe77cb4c9c6beea370",
      );
      expect(crypto.createHash(name).update("x").digest("hex")).toBe(crypto.hash("blake2b512", "x"));
    }
  });

  it("that only Bun has", () => {
    for (const [name, canonical] of [
      ["sha128", "sha1"],
      ["sha-512_224", "sha512-224"],
      ["sha-512224", "sha512-224"],
      ["sha-512_256", "sha512-256"],
      ["sha-512256", "sha512-256"],
    ]) {
      for (const [, call] of functions) expect(call(name)).toBe(call(canonical));
    }
    expect(crypto.pbkdf2Sync("password", "salt", 1, 8, "blake2b256").toString("hex")).toBe("2ae662d8acc3fd98");
  });

  it.each(functions)("that %s() does not know", (label, call) => {
    for (const name of ["nope", "", "sha256 ", "sha-257", "rsa-sha", "sha256WithRSA", "\u017fha256"]) {
      expect(() => call(name)).toThrow(
        label === "createHash"
          ? expect.objectContaining({ name: "Error", message: "Digest method not supported" })
          : label === "hash"
            ? expect.objectContaining({ name: "Error", message: `Digest method ${name} is not supported` })
            : expect.objectContaining({ name: "TypeError", code: "ERR_CRYPTO_INVALID_DIGEST" }),
      );
    }
  });

  it("are all in getHashes()", () => {
    const hashes = crypto.getHashes();
    expect(hashes).toEqual([...new Set(hashes)].toSorted());
    expect(hashes).toEqual(
      expect.arrayContaining([
        "RSA-SHA256",
        "blake2b512",
        "md5-sha1",
        "rmd160",
        "sha-256",
        "sha256",
        "sha512-256",
        "ssl3-md5",
      ]),
    );
    for (const name of hashes) {
      const digest = crypto.createHash(name).update("x").digest("hex");
      expect([name, crypto.hash(name, "x")]).toEqual([name, digest]);
      expect([name, crypto.hash(name.toUpperCase(), "x")]).toEqual([name, digest]);
      // Node's tests count on these two for every name in the list.
      expect([name, crypto.pbkdf2Sync("password", "salt", 1, 8, name)]).toEqual([name, expect.any(Buffer)]);
      expect([name, crypto.hkdfSync(name, "key", "salt", "info", 8)]).toEqual([name, expect.any(ArrayBuffer)]);
    }
    hashes.length = 0;
    expect(crypto.getHashes()).not.toBeEmpty();
  });
});

describe("crypto", () => {
  for (let Hash of HashClasses) {
    for (let [input, label] of [
      ["hello world", '"hello world"'],
      ["hello world".repeat(20).slice(), '"hello world" x 20'],
      ["", "empty string"],
      ["a", '"a"'],
    ]) {
      describe(label, () => {
        gc(true);

        it(`${Hash.name} base64`, () => {
          gc(true);
          const result = new Hash();
          result.update(input);
          expect(typeof result.digest("base64")).toBe("string");
          gc(true);
        });

        it(`${Hash.name} hash base64`, () => {
          Hash.hash(input, "base64");
          gc(true);
        });

        it(`${Hash.name} hex`, () => {
          const result = new Hash();
          result.update(input);
          expect(typeof result.digest("hex")).toBe("string");
          gc(true);
        });

        it(`${Hash.name} hash hex`, () => {
          expect(typeof Hash.hash(input, "hex")).toBe("string");
          gc(true);
        });

        it(`${Hash.name} buffer`, () => {
          var buf = new Uint8Array(256);
          const result = new Hash();

          result.update(input);
          expect(result.digest(buf)).toBe(buf);
          expect(buf[0] != 0).toBe(true);
          gc(true);
        });

        it(`${Hash.name} buffer`, () => {
          var buf = new Uint8Array(256);

          expect(Hash.hash(input, buf) instanceof Uint8Array).toBe(true);
          gc(true);
        });

        it(`${Hash.name} hash matches the streaming digest and node:crypto`, () => {
          const nodeName = Hash.name.toLowerCase().replace("_", "-");
          const expected = crypto.createHash(nodeName).update(input).digest();

          expect(Hash.hash(input, "hex")).toBe(expected.toString("hex"));
          expect(Hash.hash(input, "base64")).toBe(new Hash().update(input).digest("base64"));

          const buf = new Uint8Array(256).fill(0xa5);
          expect(Hash.hash(input, buf)).toBe(buf);
          expect(Buffer.from(buf.subarray(0, expected.byteLength))).toEqual(expected);
          expect(buf.subarray(expected.byteLength).every(byte => byte === 0xa5)).toBe(true);
        });
      });
    }
  }
});

describe("crypto.createSign()/.verifySign()", () => {
  it.each(hashesFixture)(
    "should create and verify digital signature for %s",
    async (alg, privKey, pubKey, expectedSign) => {
      const p = await Bun.file(`${__dirname}/${privKey}`).text();
      const sign = crypto.createSign(alg).update("text").sign(p, "base64");

      expect(sign).toEqual(expectedSign);

      const verify = crypto
        .createVerify(alg)
        .update("text")
        .verify(await Bun.file(`${__dirname}/${pubKey}`).text(), sign, "base64");
      expect(verify).toBeTrue();
    },
  );
});

describe("crypto.sign()/crypto.verify() interoperate with OpenSSL", () => {
  // Signatures from OpenSSL (Python's `cryptography`), an implementation independent of Bun's.
  const message = Buffer.from("rind in bun");
  const ed25519 = { jwk: {"kty": "OKP", "crv": "Ed25519", "x": "ipQvnZFEoK-oWH3L1NXl3Dnz17cRrzOV-XM-1N3Ry_I", "d": "9ajlRlaDZOSDM2GUGlL7cQJPybwA7hGdZFiIM-dxVuc"}, signature: "9a8cda00c7a90caf3d8ac3140ba92c48129cac6e3ef646edef9973e82c5220aec5ac070e7b984ae090a2de03ad6fc803440f9596c6754bef0b3a0d98b4cbec0d" };
  const ecdsa = [
    { curve: "P-384", hash: "sha384", jwk: {"kty": "EC", "crv": "P-384", "x": "Ih8bfHO_FwLZxv0hpwZFcK_5vrRNn63emOwqgMSRuCJwlKehp-EcsMF4bzwvcDPU", "y": "l29hu1iSPkoaTa5yjXC2NIf7h3C1Bx82QZQ4uPxodumhqrYdfMTQjyhXcSkwhjNG", "d": "AcvZnjuooXTtZzn3ZZU2LMXLjb1qgdOCX2gXl1WkBwr_7_Gc6rGHQmZYPQTbZbU-"}, der: "3065023100cb40240d092113e2785f363ec261a8f2bc59a001341625b7006a2f239800799239417ab1d1bf86c47d0cdeb87bc4bcab023058819ccf512a863aa042bbda2c8be86993a23a815306c8dbf735c598e02488da91265386c854e832d6b8c8a76d8a0d35", p1363: "cb40240d092113e2785f363ec261a8f2bc59a001341625b7006a2f239800799239417ab1d1bf86c47d0cdeb87bc4bcab58819ccf512a863aa042bbda2c8be86993a23a815306c8dbf735c598e02488da91265386c854e832d6b8c8a76d8a0d35" },
    { curve: "P-521", hash: "sha512", jwk: {"kty": "EC", "crv": "P-521", "x": "Ae7p4LIan2XCk-qFbp7JUsZBUnx5Cy34iuZffYwIJQ92p4CKCgDKC3KUuvTNPCLVJz3RFqCBWGaNAkYfpXGv77P0", "y": "AYAVZnnQTnBeif72K13AUxE_st574OqmU-ZJkcIHGpFn0nEmMVfaI05W0mGHXdI0zebQNx7gF_kfOMknAu7ix8b0", "d": "AKCLThTsPNIdEb5mwTCu6J-8YxoGk9dgklIaQabnOdZa4exTHlQGmNiRh-mUGh5MlW4daw8ML4DIxigXRaktkFqE"}, der: "30818702420112108d7b3b8e4967570e0bad202151732f61f84300c18588dd8116cb712f0d84099f60bdc5de785c078cdb42b037f60ca52ae95f67e141af94dc36650c5fc0f47e02411766c45fb151c31d8896742820c2a3338a505ff45a314ac2ce23cac365114d783e7989058a8b104e22f4b8b099a4183133786c3f5cfa2a7ecdd19992c9b186944c", p1363: "0112108d7b3b8e4967570e0bad202151732f61f84300c18588dd8116cb712f0d84099f60bdc5de785c078cdb42b037f60ca52ae95f67e141af94dc36650c5fc0f47e001766c45fb151c31d8896742820c2a3338a505ff45a314ac2ce23cac365114d783e7989058a8b104e22f4b8b099a4183133786c3f5cfa2a7ecdd19992c9b186944c" },
  ];

  it("Ed25519", () => {
    const privateKey = crypto.createPrivateKey({ key: ed25519.jwk, format: "jwk" });
    const publicKey = crypto.createPublicKey(privateKey);
    const expected = Buffer.from(ed25519.signature, "hex");
    expect(crypto.sign(null, message, privateKey)).toEqual(expected);
    expect(crypto.verify(null, message, publicKey, expected)).toBe(true);
    expect(crypto.verify(null, message, privateKey, expected)).toBe(true);
    const tampered = Buffer.from(expected);
    tampered[3] ^= 1;
    expect(crypto.verify(null, message, publicKey, tampered)).toBe(false);
    expect(crypto.verify(null, message, publicKey, expected.subarray(1))).toBe(false);
    // Ed25519 takes no digest.
    expect(() => crypto.sign("sha256", message, privateKey)).toThrow();
    expect(() => crypto.verify("sha256", message, publicKey, expected)).toThrow();
  });

  for (const { curve, hash, jwk, der, p1363 } of ecdsa) {
    it(`ECDSA ${curve} with ${hash}`, () => {
      const privateKey = crypto.createPrivateKey({ key: jwk, format: "jwk" });
      const publicKey = crypto.createPublicKey(privateKey);
      const derSig = Buffer.from(der, "hex");
      const p1363Sig = Buffer.from(p1363, "hex");
      expect(crypto.verify(hash, message, publicKey, derSig)).toBe(true);
      expect(crypto.verify(hash, message, privateKey, derSig)).toBe(true);
      expect(crypto.verify(hash, message, { key: publicKey, dsaEncoding: "ieee-p1363" }, p1363Sig)).toBe(true);

      const tampered = Buffer.from(derSig);
      tampered[tampered.length - 1] ^= 1;
      expect(crypto.verify(hash, message, publicKey, tampered)).toBe(false);
      expect(crypto.verify(hash, message, publicKey, Buffer.concat([derSig, Buffer.from([0])]))).toBe(false);
      // DER with a needless leading zero on r decodes to the same r, but is not DER.
      const rLen = derSig[derSig[1] & 0x80 ? 4 : 3];
      const rStart = derSig[1] & 0x80 ? 5 : 4;
      const r = derSig.subarray(rStart, rStart + rLen);
      const rest = derSig.subarray(rStart + rLen);
      const body = Buffer.concat([Buffer.from([0x02, rLen + 1, 0]), r, rest]);
      const lenBytes = body.length < 0x80 ? Buffer.from([body.length]) : Buffer.from([0x81, body.length]);
      const padded = Buffer.concat([Buffer.from([0x30]), lenBytes, body]);
      expect(crypto.verify(hash, message, publicKey, padded)).toBe(false);

      const ours = crypto.sign(hash, message, privateKey);
      expect(crypto.verify(hash, message, publicKey, ours)).toBe(true);
      const oursP1363 = crypto.sign(hash, message, { key: privateKey, dsaEncoding: "ieee-p1363" });
      expect(oursP1363.length).toBe(p1363Sig.length);
      expect(crypto.verify(hash, message, { key: publicKey, dsaEncoding: "ieee-p1363" }, oursP1363)).toBe(true);
      // The sign() of a Sign object hashes on its own path; both agree.
      expect(crypto.createVerify(hash).update(message).verify(publicKey, ours)).toBe(true);
      expect(crypto.verify(hash, message, publicKey, crypto.createSign(hash).update(message).sign(privateKey))).toBe(true);
      // A hash other than the curve's own signs and verifies too.
      const sha256 = crypto.sign("sha256", message, privateKey);
      expect(crypto.verify("sha256", message, publicKey, sha256)).toBe(true);
      expect(crypto.verify(hash, message, publicKey, sha256)).toBe(false);
    });
  }
});

it("should send cipher events in the right order", async () => {
  const package_dir = tmpdirSync();
  const fixture_path = path.join(package_dir, "fixture.js");

  await Bun.write(
    fixture_path,
    String.raw`
    function patchEmitter(emitter, prefix) {
      var oldEmit = emitter.emit;

      emitter.emit = function () {
        console.log([prefix, arguments[0]]);
        oldEmit.apply(emitter, arguments);
      };
    }

    const crypto = require("node:crypto");

    const plaintext = "Out of the mountain of despair, a stone of hope.";

    const key = Buffer.from("3fad401bb178066f201b55368712530229d6329a5e2c05f48ff36ca65792d21d", "hex");
    const iv = Buffer.from("22371787d3e04a6589d8a1de50c81208", "hex");

    // Since Node 26, read() with no size returns one buffered chunk at a time,
    // so drain the stream instead of assuming a single read returns everything.
    function readAll(stream) {
      const chunks = [];
      for (let chunk; (chunk = stream.read()) !== null; ) chunks.push(chunk);
      return Buffer.concat(chunks);
    }

    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    patchEmitter(cipher, "cipher");
    cipher.end(plaintext);
    let ciph = readAll(cipher);
    console.log([1, ciph.toString("hex")]);

    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    patchEmitter(decipher, "decipher");
    decipher.end(ciph);
    let dciph = readAll(decipher);
    console.log([2, dciph.toString("hex")]);
    let txt = dciph.toString("utf8");

    console.log([3, plaintext]);
    console.log([4, txt]);
    `,
  );

  const { stdout, stderr } = Bun.spawn({
    cmd: [bunExe(), "run", fixture_path],
    stdout: "pipe",
    stdin: "ignore",
    stderr: "pipe",
    env: bunEnv,
  });
  const err = await stderr.text();
  expect(err).toBeEmpty();
  const out = await stdout.text();
  // Matches Node 26 output for the same fixture (verified byte-for-byte
  // modulo quote style).
  expect(out.split("\n")).toEqual([
    `[ "cipher", "readable" ]`,
    `[ "cipher", "prefinish" ]`,
    `[ "cipher", "data" ]`,
    `[ "cipher", "data" ]`,
    `[ 1, "dfb6b7e029be3ad6b090349ed75931f28f991b52ca9a89f5bf6f82fa1c87aa2d624bd77701dcddfcceaf3add7d66ce06ced17aebca4cb35feffc4b8b9008b3c4" ]`,
    `[ "decipher", "readable" ]`,
    `[ "decipher", "prefinish" ]`,
    `[ "decipher", "data" ]`,
    `[ 2, "4f7574206f6620746865206d6f756e7461696e206f6620646573706169722c20612073746f6e65206f6620686f70652e" ]`,
    `[ 3, "Out of the mountain of despair, a stone of hope." ]`,
    `[ 4, "Out of the mountain of despair, a stone of hope." ]`,
    `[ "cipher", "finish" ]`,
    `[ "cipher", "end" ]`,
    `[ "decipher", "finish" ]`,
    `[ "decipher", "end" ]`,
    `[ "cipher", "close" ]`,
    `[ "decipher", "close" ]`,
    ``,
  ]);
});
