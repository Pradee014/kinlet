/**
 * Storage for the hosted MCP endpoint: OAuth clients, pending authorizations, codes, tokens,
 * and connections. A connection is one agent credential, encrypted at rest, tied to one person.
 * Tokens are stored hashed; the plaintext exists only in the client's hands.
 */
import Database from "better-sqlite3";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

export interface OAuthClient {
  id: string;
  name: string;
  redirectUris: string[];
  createdAt: string;
}

export interface PendingAuth {
  id: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state: string | null;
  scope: string | null;
  resource: string | null;
  createdAt: string;
}

export interface AuthCode {
  code: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  connectionId: string;
  resource: string | null;
  expiresAt: number;
}

export interface TokenRow {
  hash: string;
  kind: "access" | "refresh";
  clientId: string;
  connectionId: string;
  expiresAt: number;
  revokedAt: string | null;
}

export interface Connection {
  id: string;
  userId: string;
  serial: string;
  clientId: string;
  createdAt: string;
  revokedAt: string | null;
}

export function sha256hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export class RemoteStore {
  private readonly db: Database.Database;

  /** `secret` is 32 bytes used to encrypt agent credentials at rest (AES-256-GCM). */
  constructor(path: string, private readonly secret: Uint8Array) {
    if (secret.length !== 32) throw new Error("remote store secret must be 32 bytes");
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS oauth_clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, redirect_uris TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS pending_auth (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, code_challenge TEXT NOT NULL, state TEXT, scope TEXT, resource TEXT, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS auth_codes (code TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, code_challenge TEXT NOT NULL, connection_id TEXT NOT NULL, resource TEXT, expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS tokens (hash TEXT PRIMARY KEY, kind TEXT NOT NULL, client_id TEXT NOT NULL, connection_id TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked_at TEXT);
      CREATE TABLE IF NOT EXISTS connections (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, serial TEXT NOT NULL, client_id TEXT NOT NULL, credential_enc BLOB NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT);
      CREATE INDEX IF NOT EXISTS connections_user ON connections(user_id);
    `);
  }

  // ---- clients ----
  insertClient(c: OAuthClient): void {
    this.db.prepare("INSERT INTO oauth_clients (id, name, redirect_uris, created_at) VALUES (?, ?, ?, ?)").run(c.id, c.name, JSON.stringify(c.redirectUris), c.createdAt);
  }
  getClient(id: string): OAuthClient | undefined {
    const r = this.db.prepare("SELECT id, name, redirect_uris, created_at FROM oauth_clients WHERE id = ?").get(id) as Record<string, string> | undefined;
    return r ? { id: r["id"] as string, name: r["name"] as string, redirectUris: JSON.parse(r["redirect_uris"] as string) as string[], createdAt: r["created_at"] as string } : undefined;
  }

  // ---- pending authorizations ----
  insertPending(p: PendingAuth): void {
    this.db.prepare("INSERT INTO pending_auth (id, client_id, redirect_uri, code_challenge, state, scope, resource, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(p.id, p.clientId, p.redirectUri, p.codeChallenge, p.state, p.scope, p.resource, p.createdAt);
  }
  takePending(id: string, maxAgeMs: number): PendingAuth | undefined {
    const r = this.db.prepare("SELECT id, client_id, redirect_uri, code_challenge, state, scope, resource, created_at FROM pending_auth WHERE id = ?").get(id) as Record<string, string | null> | undefined;
    this.db.prepare("DELETE FROM pending_auth WHERE id = ?").run(id);
    if (!r) return undefined;
    if (Date.now() - Date.parse(r["created_at"] as string) > maxAgeMs) return undefined;
    return { id: r["id"] as string, clientId: r["client_id"] as string, redirectUri: r["redirect_uri"] as string, codeChallenge: r["code_challenge"] as string, state: r["state"] ?? null, scope: r["scope"] ?? null, resource: r["resource"] ?? null, createdAt: r["created_at"] as string };
  }
  peekPending(id: string): PendingAuth | undefined {
    const r = this.db.prepare("SELECT id, client_id, redirect_uri, code_challenge, state, scope, resource, created_at FROM pending_auth WHERE id = ?").get(id) as Record<string, string | null> | undefined;
    return r ? { id: r["id"] as string, clientId: r["client_id"] as string, redirectUri: r["redirect_uri"] as string, codeChallenge: r["code_challenge"] as string, state: r["state"] ?? null, scope: r["scope"] ?? null, resource: r["resource"] ?? null, createdAt: r["created_at"] as string } : undefined;
  }

  // ---- codes ----
  insertCode(c: AuthCode): void {
    this.db.prepare("INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge, connection_id, resource, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(sha256hex(c.code), c.clientId, c.redirectUri, c.codeChallenge, c.connectionId, c.resource, c.expiresAt);
  }
  takeCode(code: string): AuthCode | undefined {
    const h = sha256hex(code);
    const r = this.db.prepare("SELECT client_id, redirect_uri, code_challenge, connection_id, resource, expires_at FROM auth_codes WHERE code = ?").get(h) as Record<string, unknown> | undefined;
    this.db.prepare("DELETE FROM auth_codes WHERE code = ?").run(h);
    if (!r) return undefined;
    return { code, clientId: r["client_id"] as string, redirectUri: r["redirect_uri"] as string, codeChallenge: r["code_challenge"] as string, connectionId: r["connection_id"] as string, resource: (r["resource"] as string | null) ?? null, expiresAt: r["expires_at"] as number };
  }

  // ---- tokens ----
  insertToken(plain: string, t: Omit<TokenRow, "hash" | "revokedAt">): void {
    this.db.prepare("INSERT INTO tokens (hash, kind, client_id, connection_id, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, NULL)").run(sha256hex(plain), t.kind, t.clientId, t.connectionId, t.expiresAt);
  }
  getToken(plain: string): TokenRow | undefined {
    const r = this.db.prepare("SELECT hash, kind, client_id, connection_id, expires_at, revoked_at FROM tokens WHERE hash = ?").get(sha256hex(plain)) as Record<string, unknown> | undefined;
    return r ? { hash: r["hash"] as string, kind: r["kind"] as TokenRow["kind"], clientId: r["client_id"] as string, connectionId: r["connection_id"] as string, expiresAt: r["expires_at"] as number, revokedAt: (r["revoked_at"] as string | null) ?? null } : undefined;
  }
  revokeToken(plain: string): void {
    this.db.prepare("UPDATE tokens SET revoked_at = ? WHERE hash = ?").run(new Date().toISOString(), sha256hex(plain));
  }
  revokeTokensForConnection(connectionId: string): void {
    this.db.prepare("UPDATE tokens SET revoked_at = ? WHERE connection_id = ? AND revoked_at IS NULL").run(new Date().toISOString(), connectionId);
  }

  // ---- connections (credential encrypted) ----
  private encrypt(plaintext: string): Buffer {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.secret, iv);
    const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), enc]);
  }
  private decrypt(blob: Buffer): string {
    const iv = blob.subarray(0, 12);
    const tag = blob.subarray(12, 28);
    const enc = blob.subarray(28);
    const decipher = createDecipheriv("aes-256-gcm", this.secret, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
  }

  insertConnection(c: Omit<Connection, "revokedAt">, credentialJson: string): void {
    this.db.prepare("INSERT INTO connections (id, user_id, serial, client_id, credential_enc, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, NULL)")
      .run(c.id, c.userId, c.serial, c.clientId, this.encrypt(credentialJson), c.createdAt);
  }
  getConnection(id: string): Connection | undefined {
    const r = this.db.prepare("SELECT id, user_id, serial, client_id, created_at, revoked_at FROM connections WHERE id = ?").get(id) as Record<string, unknown> | undefined;
    return r ? { id: r["id"] as string, userId: r["user_id"] as string, serial: r["serial"] as string, clientId: r["client_id"] as string, createdAt: r["created_at"] as string, revokedAt: (r["revoked_at"] as string | null) ?? null } : undefined;
  }
  /** Decrypts the credential. Callers keep it in memory only. */
  credentialFor(id: string): string | undefined {
    const r = this.db.prepare("SELECT credential_enc FROM connections WHERE id = ? AND revoked_at IS NULL").get(id) as { credential_enc: Buffer } | undefined;
    return r ? this.decrypt(r.credential_enc) : undefined;
  }
  connectionsForUser(userId: string): Connection[] {
    const rows = this.db.prepare("SELECT id FROM connections WHERE user_id = ? ORDER BY created_at DESC").all(userId) as { id: string }[];
    return rows.map((r) => this.getConnection(r.id)).filter((c): c is Connection => c !== undefined);
  }
  connectionForSerial(serial: string): Connection | undefined {
    const r = this.db.prepare("SELECT id FROM connections WHERE serial = ? AND revoked_at IS NULL LIMIT 1").get(serial) as { id: string } | undefined;
    return r ? this.getConnection(r.id) : undefined;
  }
  revokeConnection(id: string): void {
    this.db.prepare("UPDATE connections SET revoked_at = ?, credential_enc = x'00' WHERE id = ? AND revoked_at IS NULL").run(new Date().toISOString(), id);
    this.revokeTokensForConnection(id);
  }
}
