/**
 * Ed25519 via WebCrypto only. Works in Node 22+, Chrome, Safari 17+, Firefox.
 * Private keys are CryptoKey objects; by default they are created non-extractable so the
 * bytes can never be read back by JavaScript. Nothing here serializes a private key.
 */
import { base58btcDecode, base58btcEncode, concatBytes, utf8Encode } from "./encoding.js";

const subtle = (): SubtleCrypto => {
  const c = globalThis.crypto;
  if (!c || !c.subtle) throw new Error("WebCrypto is not available in this environment");
  return c.subtle;
};

/** multicodec prefix for ed25519-pub (0xed) as a varint: 0xed 0x01 */
const ED25519_PUB_MULTICODEC = new Uint8Array([0xed, 0x01]);

export interface Signer {
  /** did:key of the public key. */
  readonly did: string;
  /** Raw 32-byte Ed25519 public key. */
  readonly publicKey: Uint8Array;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export interface KeyPair extends Signer {
  readonly privateKey: CryptoKey;
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  return new Uint8Array(await subtle().digest("SHA-256", buf));
}

export function didKeyFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  return "did:key:z" + base58btcEncode(concatBytes(ED25519_PUB_MULTICODEC, publicKey));
}

/** Decodes a did:key for Ed25519. Throws on any other key type. */
export function publicKeyFromDidKey(did: string): Uint8Array {
  if (!did.startsWith("did:key:z")) throw new Error("not a base58btc did:key");
  const idPart = did.slice("did:key:".length);
  if (idPart.includes("#") || idPart.includes("/") || idPart.includes("?")) {
    throw new Error("did:key must not contain fragment, path or query");
  }
  const bytes = base58btcDecode(idPart.slice(1));
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new Error("did:key is not an Ed25519 key");
  }
  return bytes.slice(2);
}

/** The verification method id for a did:key: did + "#" + method-specific id. */
export function verificationMethodForDid(did: string): string {
  return did + "#" + did.slice("did:key:".length);
}

async function toSigner(publicKey: Uint8Array, privateKey: CryptoKey): Promise<KeyPair> {
  const did = didKeyFromPublicKey(publicKey);
  return {
    did,
    publicKey,
    privateKey,
    async sign(message: Uint8Array): Promise<Uint8Array> {
      const buf = message.buffer.slice(message.byteOffset, message.byteOffset + message.byteLength) as ArrayBuffer;
      return new Uint8Array(await subtle().sign({ name: "Ed25519" }, privateKey, buf));
    },
  };
}

/**
 * Generates an Ed25519 key pair. `extractable` defaults to false: the private key can be used
 * but never exported. Pass true only for an agent key that must be delivered to the agent runtime
 * once (see exportPrivateKeyOnce).
 */
export async function generateKeyPair(opts: { extractable?: boolean } = {}): Promise<KeyPair> {
  const extractable = opts.extractable ?? false;
  const kp = (await subtle().generateKey({ name: "Ed25519" }, extractable, ["sign", "verify"])) as CryptoKeyPair;
  const pub = new Uint8Array(await subtle().exportKey("raw", kp.publicKey));
  return toSigner(pub, kp.privateKey);
}

/**
 * Exports a private key as PKCS#8 bytes. Only works for keys created with extractable: true.
 * Intended for the single hand-off of an agent key to its runtime. Callers must not log or persist
 * the result beyond that hand-off.
 */
export async function exportPrivateKeyOnce(kp: KeyPair): Promise<Uint8Array> {
  return new Uint8Array(await subtle().exportKey("pkcs8", kp.privateKey));
}

/**
 * Imports a PKCS#8 Ed25519 private key together with its known public key, as a non-extractable
 * signer. WebCrypto cannot derive the public key from a non-extractable private key, so the agent
 * hand-off carries both; a mismatch is detected by a sign/verify probe.
 */
export async function importPrivateKeyWithPublic(pkcs8: Uint8Array, publicKey: Uint8Array): Promise<KeyPair> {
  const buf = pkcs8.buffer.slice(pkcs8.byteOffset, pkcs8.byteOffset + pkcs8.byteLength) as ArrayBuffer;
  const priv = await subtle().importKey("pkcs8", buf, { name: "Ed25519" }, false, ["sign"]);
  const kp = await toSigner(publicKey, priv);
  // Self-check: sign and verify a probe so a mismatched public key fails loudly here, not later.
  const probe = utf8Encode("kinlet-key-probe");
  const sig = await kp.sign(probe);
  if (!(await verify(publicKey, probe, sig))) throw new Error("private key does not match public key");
  return kp;
}

export async function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  const pubBuf = publicKey.buffer.slice(publicKey.byteOffset, publicKey.byteOffset + publicKey.byteLength) as ArrayBuffer;
  const key = await subtle().importKey("raw", pubBuf, { name: "Ed25519" }, false, ["verify"]);
  const sigBuf = signature.buffer.slice(signature.byteOffset, signature.byteOffset + signature.byteLength) as ArrayBuffer;
  const msgBuf = message.buffer.slice(message.byteOffset, message.byteOffset + message.byteLength) as ArrayBuffer;
  try {
    return await subtle().verify({ name: "Ed25519" }, key, sigBuf, msgBuf);
  } catch {
    return false;
  }
}
