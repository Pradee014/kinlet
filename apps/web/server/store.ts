import Database from "better-sqlite3";

export interface User {
  id: string;
  username: string;
  createdAt: string;
}

export interface Passkey {
  id: string; // base64url credential id
  userId: string;
  publicKey: Uint8Array;
  counter: number;
  transports: string | null;
  createdAt: string;
}

export interface Session {
  id: string;
  userId: string;
  createdAt: string;
  /** Last time the user completed a passkey assertion (fresh-auth gate for signing). */
  lastAuthAt: string;
}

export class WebStore {
  private readonly db: Database.Database;
  constructor(path = ":memory:") {
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS passkeys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), public_key BLOB NOT NULL, counter INTEGER NOT NULL, transports TEXT, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, last_auth_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS challenges (key TEXT PRIMARY KEY, challenge TEXT NOT NULL, expires_at INTEGER NOT NULL);
    `);
  }

  getUserByName(username: string): User | undefined {
    const r = this.db.prepare("SELECT id, username, created_at FROM users WHERE username = ?").get(username) as Record<string, string> | undefined;
    return r ? { id: r["id"] as string, username: r["username"] as string, createdAt: r["created_at"] as string } : undefined;
  }
  getUser(id: string): User | undefined {
    const r = this.db.prepare("SELECT id, username, created_at FROM users WHERE id = ?").get(id) as Record<string, string> | undefined;
    return r ? { id: r["id"] as string, username: r["username"] as string, createdAt: r["created_at"] as string } : undefined;
  }
  insertUser(u: User): void {
    this.db.prepare("INSERT INTO users (id, username, created_at) VALUES (?, ?, ?)").run(u.id, u.username, u.createdAt);
  }

  passkeysFor(userId: string): Passkey[] {
    const rows = this.db.prepare("SELECT id, user_id, public_key, counter, transports, created_at FROM passkeys WHERE user_id = ?").all(userId) as Record<string, unknown>[];
    return rows.map((r) => ({ id: r["id"] as string, userId: r["user_id"] as string, publicKey: new Uint8Array(r["public_key"] as Buffer), counter: r["counter"] as number, transports: (r["transports"] as string | null) ?? null, createdAt: r["created_at"] as string }));
  }
  getPasskey(id: string): Passkey | undefined {
    const r = this.db.prepare("SELECT id, user_id, public_key, counter, transports, created_at FROM passkeys WHERE id = ?").get(id) as Record<string, unknown> | undefined;
    return r ? { id: r["id"] as string, userId: r["user_id"] as string, publicKey: new Uint8Array(r["public_key"] as Buffer), counter: r["counter"] as number, transports: (r["transports"] as string | null) ?? null, createdAt: r["created_at"] as string } : undefined;
  }
  insertPasskey(p: Passkey): void {
    this.db.prepare("INSERT INTO passkeys (id, user_id, public_key, counter, transports, created_at) VALUES (?, ?, ?, ?, ?, ?)").run(p.id, p.userId, Buffer.from(p.publicKey), p.counter, p.transports, p.createdAt);
  }
  updateCounter(id: string, counter: number): void {
    this.db.prepare("UPDATE passkeys SET counter = ? WHERE id = ?").run(counter, id);
  }

  putChallenge(key: string, challenge: string, ttlMs: number): void {
    this.db.prepare("INSERT OR REPLACE INTO challenges (key, challenge, expires_at) VALUES (?, ?, ?)").run(key, challenge, Date.now() + ttlMs);
  }
  takeChallenge(key: string): string | undefined {
    const r = this.db.prepare("SELECT challenge, expires_at FROM challenges WHERE key = ?").get(key) as { challenge: string; expires_at: number } | undefined;
    this.db.prepare("DELETE FROM challenges WHERE key = ?").run(key);
    if (!r || r.expires_at < Date.now()) return undefined;
    return r.challenge;
  }

  insertSession(s: Session): void {
    this.db.prepare("INSERT INTO sessions (id, user_id, created_at, last_auth_at) VALUES (?, ?, ?, ?)").run(s.id, s.userId, s.createdAt, s.lastAuthAt);
  }
  getSession(id: string): Session | undefined {
    const r = this.db.prepare("SELECT id, user_id, created_at, last_auth_at FROM sessions WHERE id = ?").get(id) as Record<string, string> | undefined;
    return r ? { id: r["id"] as string, userId: r["user_id"] as string, createdAt: r["created_at"] as string, lastAuthAt: r["last_auth_at"] as string } : undefined;
  }
  touchSession(id: string, lastAuthAt: string): void {
    this.db.prepare("UPDATE sessions SET last_auth_at = ? WHERE id = ?").run(lastAuthAt, id);
  }
  deleteSession(id: string): void {
    this.db.prepare("DELETE FROM sessions WHERE id = ?").run(id);
  }
}
