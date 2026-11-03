/** 32-byte secret for encrypting connection credentials: from env (base64url) or a 0600 file. */
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname } from "node:path";

export function loadOrCreateSecret(path: string, env = process.env["KINLET_REMOTE_SECRET"]): Uint8Array {
  if (env) {
    const b = Buffer.from(env, "base64url");
    if (b.length !== 32) throw new Error("KINLET_REMOTE_SECRET must be 32 bytes, base64url");
    return new Uint8Array(b);
  }
  if (existsSync(path)) return new Uint8Array(Buffer.from(readFileSync(path, "utf8").trim(), "base64url"));
  const secret = randomBytes(32);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, secret.toString("base64url"), { mode: 0o600 });
  chmodSync(path, 0o600);
  return new Uint8Array(secret);
}
