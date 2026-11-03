/**
 * The person's root key: a non-extractable Ed25519 CryptoKey stored in IndexedDB.
 * It can be used by this origin in this browser profile and nowhere else. Before any signing,
 * the app requires a fresh passkey assertion (see auth.ts), which is the user gesture gate.
 */
import { didKeyFromPublicKey, type Signer } from "@kinlet/core";

const DB = "kinlet";
const STORE_KEYS = "keys";
const STORE_AGENTS = "agents";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_KEYS)) db.createObjectStore(STORE_KEYS);
      if (!db.objectStoreNames.contains(STORE_AGENTS)) db.createObjectStore(STORE_AGENTS, { keyPath: "serial" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx<T>(store: string, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return openDb().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const t = db.transaction(store, mode);
        const r = fn(t.objectStore(store));
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error);
      }),
  );
}

interface StoredRoot {
  privateKey: CryptoKey;
  publicKey: Uint8Array;
}

export interface RootKey extends Signer {
  /** Signs only after `gate` resolves; the gate performs the passkey check. */
  withGate(gate: () => Promise<void>): Signer;
}

export async function loadOrCreateRootKey(userId: string): Promise<RootKey> {
  const id = "root:" + userId;
  let stored = (await tx<StoredRoot | undefined>(STORE_KEYS, "readonly", (s) => s.get(id))) ?? undefined;
  if (!stored) {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    stored = { privateKey: kp.privateKey, publicKey };
    await tx(STORE_KEYS, "readwrite", (s) => s.put(stored, id));
  }
  const { privateKey, publicKey } = stored;
  const did = didKeyFromPublicKey(publicKey);
  const sign = async (message: Uint8Array): Promise<Uint8Array> => {
    const buf = message.buffer.slice(message.byteOffset, message.byteOffset + message.byteLength) as ArrayBuffer;
    return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, buf));
  };
  const gated = (gate: () => Promise<void>): Signer => ({
    did,
    publicKey,
    async sign(m) {
      await gate();
      return sign(m);
    },
  });
  return {
    did,
    publicKey,
    sign: async () => {
      throw new Error("root key must be used through withGate()");
    },
    withGate: gated,
  };
}

export interface StoredAgent {
  serial: string;
  card: unknown;
  createdAt: string;
}

export const agents = {
  all: (): Promise<StoredAgent[]> => tx<StoredAgent[]>(STORE_AGENTS, "readonly", (s) => s.getAll()),
  get: (serial: string): Promise<StoredAgent | undefined> => tx<StoredAgent | undefined>(STORE_AGENTS, "readonly", (s) => s.get(serial)),
  put: (a: StoredAgent): Promise<unknown> => tx(STORE_AGENTS, "readwrite", (s) => s.put(a)),
};
