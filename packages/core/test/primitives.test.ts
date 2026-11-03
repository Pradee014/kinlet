import { describe, expect, it } from "vitest";
import {
  base58btcDecode,
  base58btcEncode,
  base64urlDecode,
  base64urlEncode,
  bytesEqual,
  checkEvent,
  checkRevocation,
  didKeyFromPublicKey,
  eventHash,
  exportPrivateKeyOnce,
  GENESIS_HASH,
  generateKeyPair,
  importPrivateKeyWithPublic,
  jcs,
  newSerial,
  publicKeyFromDidKey,
  signDocument,
  signEvent,
  signRevocation,
  utf8Encode,
  verify,
  verifyDocument,
} from "../src/index.js";

describe("encoding", () => {
  it("base58btc round-trips, including leading zeros", () => {
    for (const bytes of [new Uint8Array([0, 0, 1, 2, 3]), new Uint8Array([255, 254, 0]), new Uint8Array(0), new Uint8Array(32).fill(7)]) {
      expect(base58btcDecode(base58btcEncode(bytes))).toEqual(bytes);
    }
    expect(base58btcEncode(new Uint8Array([0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd]))).toBe("11233QC4");
  });

  it("base64url round-trips and rejects bad input", () => {
    const b = new Uint8Array([0, 1, 2, 250, 251, 252]);
    expect(base64urlDecode(base64urlEncode(b))).toEqual(b);
    expect(() => base64urlDecode("not+valid/")).toThrow();
  });

  it("bytesEqual is strict", () => {
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(bytesEqual(new Uint8Array([1]), new Uint8Array([1, 0]))).toBe(false);
  });

  it("serials are 20 Crockford characters and unique", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const s = newSerial();
      expect(s).toMatch(/^[0-9A-HJKMNP-TV-Z]{20}$/);
      seen.add(s);
    }
    expect(seen.size).toBe(200);
  });
});

describe("keys and did:key", () => {
  it("round-trips a public key through did:key", async () => {
    const kp = await generateKeyPair();
    expect(kp.did).toMatch(/^did:key:z6Mk/);
    expect(publicKeyFromDidKey(kp.did)).toEqual(kp.publicKey);
    expect(didKeyFromPublicKey(kp.publicKey)).toBe(kp.did);
  });

  it("rejects non-Ed25519 or malformed did:key", () => {
    expect(() => publicKeyFromDidKey("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")).toThrow(); // secp256k1
    expect(() => publicKeyFromDidKey("did:web:example.com")).toThrow();
    expect(() => publicKeyFromDidKey("did:key:z6Mk#frag")).toThrow();
  });

  it("private keys are non-extractable by default", async () => {
    const kp = await generateKeyPair();
    await expect(exportPrivateKeyOnce(kp)).rejects.toThrow();
  });

  it("agent key hand-off round-trips and detects a mismatched public key", async () => {
    const kp = await generateKeyPair({ extractable: true });
    const pkcs8 = await exportPrivateKeyOnce(kp);
    const imported = await importPrivateKeyWithPublic(pkcs8, kp.publicKey);
    const msg = utf8Encode("hello");
    expect(await verify(kp.publicKey, msg, await imported.sign(msg))).toBe(true);
    const other = await generateKeyPair();
    await expect(importPrivateKeyWithPublic(pkcs8, other.publicKey)).rejects.toThrow(/does not match/);
  });
});

describe("data integrity proofs", () => {
  it("signs and verifies; rejects tampering and wrong signer", async () => {
    const kp = await generateKeyPair();
    const other = await generateKeyPair();
    const signed = await signDocument({ a: 1, b: [1, 2, { c: "x" }] }, kp);
    expect((await verifyDocument(signed, kp.did)).ok).toBe(true);
    expect((await verifyDocument({ ...signed, a: 2 }, kp.did)).ok).toBe(false);
    expect((await verifyDocument(signed, other.did)).ok).toBe(false);
    const wrongPurpose = { ...signed, proof: { ...signed.proof, proofPurpose: "authentication" } };
    expect((await verifyDocument(wrongPurpose, kp.did)).ok).toBe(false);
  });

  it("canonicalization is key-order independent", () => {
    expect(jcs({ b: 1, a: [3, { z: 1, y: 2 }] })).toBe(jcs({ a: [3, { y: 2, z: 1 }], b: 1 }));
  });

  it("refuses to sign a document that already has a proof", async () => {
    const kp = await generateKeyPair();
    const signed = await signDocument({ a: 1 }, kp);
    await expect(signDocument(signed, kp)).rejects.toThrow(/already/);
  });
});

describe("revocations and events", () => {
  it("revocation verifies only against the issuer", async () => {
    const person = await generateKeyPair();
    const other = await generateKeyPair();
    const rev = await signRevocation({ serial: newSerial(), reason: "lost laptop" }, person);
    expect((await checkRevocation(rev, person.did)).ok).toBe(true);
    expect((await checkRevocation(rev, other.did)).ok).toBe(false);
  });

  it("events chain and a broken chain is detected", async () => {
    const agent = await generateKeyPair();
    const serial = newSerial();
    const e0 = await signEvent({ serial, seq: 0, prev: GENESIS_HASH, target: "https://shop.example.com/orders", action: { type: "read" }, outcome: "ok" }, agent);
    const c0 = await checkEvent(e0, { agentDid: agent.did, serial, seq: 0, prev: GENESIS_HASH });
    expect(c0.ok).toBe(true);
    const h0 = await eventHash(e0);
    const e1 = await signEvent({ serial, seq: 1, prev: h0, target: "https://shop.example.com/orders", action: { type: "purchase", amount: 1, currency: "USD" }, outcome: "refused:limit_exceeded" }, agent);
    expect((await checkEvent(e1, { agentDid: agent.did, serial, seq: 1, prev: h0 })).ok).toBe(true);
    expect((await checkEvent(e1, { agentDid: agent.did, serial, seq: 1, prev: GENESIS_HASH })).ok).toBe(false);
    expect((await checkEvent(e1, { agentDid: agent.did, serial, seq: 2, prev: h0 })).ok).toBe(false);
  });
});
