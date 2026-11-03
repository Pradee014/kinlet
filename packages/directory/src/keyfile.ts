/**
 * Directory signing key persistence. The key file is JSON with the PKCS#8 private key and the raw
 * public key, both base64url. It is created with mode 0600. In production, replace this with a KMS
 * or HSM-backed Signer; the app only needs the Signer interface.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { base64urlDecode, base64urlEncode, exportPrivateKeyOnce, generateKeyPair, importPrivateKeyWithPublic, type KeyPair } from "@kinlet/core";

interface KeyFile {
  version: 1;
  publicKey: string;
  privateKeyPkcs8: string;
}

export async function loadOrCreateKey(path: string): Promise<KeyPair> {
  if (existsSync(path)) {
    const raw = JSON.parse(readFileSync(path, "utf8")) as KeyFile;
    if (raw.version !== 1) throw new Error("unsupported key file version");
    return importPrivateKeyWithPublic(base64urlDecode(raw.privateKeyPkcs8), base64urlDecode(raw.publicKey));
  }
  const kp = await generateKeyPair({ extractable: true });
  const file: KeyFile = { version: 1, publicKey: base64urlEncode(kp.publicKey), privateKeyPkcs8: base64urlEncode(await exportPrivateKeyOnce(kp)) };
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(file), { mode: 0o600 });
  chmodSync(path, 0o600);
  // Re-import as non-extractable so the in-memory key cannot be exported again.
  return importPrivateKeyWithPublic(base64urlDecode(file.privateKeyPkcs8), kp.publicKey);
}
