/**
 * SQLite-backed store. Holds only what the spec allows the directory to keep:
 * serial, issuer DID, agent DID, validity window, revocation, and the signed event chain.
 * Never the card's name or permissions.
 */
import Database from "better-sqlite3";

export interface CardRow {
  serial: string;
  issuer: string;
  subject: string;
  validFrom: string;
  validUntil: string;
  registeredAt: string;
  revokedAt: string | null;
  revocationJson: string | null;
}

export interface EventRow {
  serial: string;
  seq: number;
  hash: string;
  json: string;
}

export class Store {
  private readonly db: Database.Database;

  constructor(path: string = ":memory:") {
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS cards (
        serial TEXT PRIMARY KEY,
        issuer TEXT NOT NULL,
        subject TEXT NOT NULL,
        valid_from TEXT NOT NULL,
        valid_until TEXT NOT NULL,
        registered_at TEXT NOT NULL,
        revoked_at TEXT,
        revocation_json TEXT
      );
      CREATE INDEX IF NOT EXISTS cards_issuer ON cards(issuer);
      CREATE TABLE IF NOT EXISTS events (
        serial TEXT NOT NULL REFERENCES cards(serial),
        seq INTEGER NOT NULL,
        hash TEXT NOT NULL,
        json TEXT NOT NULL,
        PRIMARY KEY (serial, seq)
      );
    `);
  }

  getCard(serial: string): CardRow | undefined {
    const r = this.db
      .prepare("SELECT serial, issuer, subject, valid_from, valid_until, registered_at, revoked_at, revocation_json FROM cards WHERE serial = ?")
      .get(serial) as Record<string, unknown> | undefined;
    if (!r) return undefined;
    return {
      serial: r["serial"] as string,
      issuer: r["issuer"] as string,
      subject: r["subject"] as string,
      validFrom: r["valid_from"] as string,
      validUntil: r["valid_until"] as string,
      registeredAt: r["registered_at"] as string,
      revokedAt: (r["revoked_at"] as string | null) ?? null,
      revocationJson: (r["revocation_json"] as string | null) ?? null,
    };
  }

  insertCard(row: Omit<CardRow, "revokedAt" | "revocationJson">): void {
    this.db
      .prepare("INSERT INTO cards (serial, issuer, subject, valid_from, valid_until, registered_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(row.serial, row.issuer, row.subject, row.validFrom, row.validUntil, row.registeredAt);
  }

  revokeCard(serial: string, revokedAt: string, revocationJson: string): void {
    this.db.prepare("UPDATE cards SET revoked_at = ?, revocation_json = ? WHERE serial = ? AND revoked_at IS NULL").run(revokedAt, revocationJson, serial);
  }

  cardsForIssuer(issuer: string): CardRow[] {
    const rows = this.db.prepare("SELECT serial FROM cards WHERE issuer = ? ORDER BY registered_at DESC").all(issuer) as { serial: string }[];
    return rows.map((r) => this.getCard(r.serial)).filter((c): c is CardRow => c !== undefined);
  }

  lastEvent(serial: string): EventRow | undefined {
    return this.db.prepare("SELECT serial, seq, hash, json FROM events WHERE serial = ? ORDER BY seq DESC LIMIT 1").get(serial) as EventRow | undefined;
  }

  insertEvent(row: EventRow): void {
    this.db.prepare("INSERT INTO events (serial, seq, hash, json) VALUES (?, ?, ?, ?)").run(row.serial, row.seq, row.hash, row.json);
  }

  events(serial: string, fromSeq = 0, limit = 200): EventRow[] {
    return this.db.prepare("SELECT serial, seq, hash, json FROM events WHERE serial = ? AND seq >= ? ORDER BY seq ASC LIMIT ?").all(serial, fromSeq, limit) as EventRow[];
  }

  close(): void {
    this.db.close();
  }
}
