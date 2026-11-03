/**
 * The directory HTTP API. See docs/CARD_FORMAT.md sections 6 to 8.
 * Every answer about a card's status is signed by the directory key.
 */
import { Hono } from "hono";
import { z } from "zod";
import {
  checkCard,
  checkEvent,
  checkRevocation,
  GENESIS_HASH,
  ProofSchema,
  signStatus,
  verifyDocument,
  type CardStatus,
  type KeyPair,
} from "@kinlet/core";
import { Store } from "./store.js";

const MAX_BODY_BYTES = 64 * 1024;
const OWNER_PROOF_MAX_AGE_MS = 60_000;

export interface DirectoryOptions {
  key: KeyPair;
  store: Store;
  /** Public origin of this directory, used in well-known. */
  publicUrl: string;
  now?: () => Date;
  /** Simple per-IP limiter for writes; requests per minute. */
  writeRatePerMinute?: number;
}

/** A person proves they own an issuer DID by signing a short-lived statement. */
const OwnerProofSchema = z
  .object({
    type: z.literal("KinletOwnerProof"),
    issuer: z.string(),
    at: z.string().datetime({ offset: false }),
    proof: ProofSchema,
  })
  .strict();

class RateLimiter {
  private readonly hits = new Map<string, number[]>();
  constructor(private readonly perMinute: number) {}
  allow(key: string, now: number): boolean {
    const windowStart = now - 60_000;
    const list = (this.hits.get(key) ?? []).filter((t) => t > windowStart);
    if (list.length >= this.perMinute) {
      this.hits.set(key, list);
      return false;
    }
    list.push(now);
    this.hits.set(key, list);
    return true;
  }
}

export function createDirectoryApp(opts: DirectoryOptions): Hono {
  const now = opts.now ?? (() => new Date());
  const { key, store } = opts;
  const limiter = new RateLimiter(opts.writeRatePerMinute ?? 120);
  const app = new Hono();

  app.use("*", async (c, next) => {
    await next();
    c.header("Cache-Control", "no-store");
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Referrer-Policy", "no-referrer");
  });

  const readJson = async (c: { req: { raw: Request } }): Promise<unknown> => {
    const len = Number(c.req.raw.headers.get("content-length") ?? "0");
    if (len > MAX_BODY_BYTES) throw new Error("body too large");
    const text = await c.req.raw.text();
    if (text.length > MAX_BODY_BYTES) throw new Error("body too large");
    return JSON.parse(text);
  };

  const clientKey = (c: { req: { raw: Request } }): string =>
    c.req.raw.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? c.req.raw.headers.get("x-real-ip") ?? "local";

  app.get("/.well-known/kinlet.json", (c) => c.json({ did: key.did, directory: opts.publicUrl, version: 1 }));

  app.get("/healthz", (c) => c.json({ ok: true }));

  // Register a card.
  app.post("/v1/cards", async (c) => {
    if (!limiter.allow(clientKey(c), now().getTime())) return c.json({ error: "rate_limited" }, 429);
    let body: unknown;
    try {
      body = await readJson(c);
    } catch {
      return c.json({ error: "bad_request" }, 400);
    }
    const check = await checkCard(body, now());
    if (!check.ok) return c.json({ error: check.reason, detail: check.detail }, 400);
    const card = check.card;
    if (card.credentialStatus.directory.replace(/\/$/, "") !== opts.publicUrl.replace(/\/$/, "")) {
      return c.json({ error: "card_malformed", detail: "card names a different directory" }, 400);
    }
    const serial = card.credentialStatus.serial;
    const existing = store.getCard(serial);
    if (existing) {
      if (existing.issuer !== card.issuer || existing.subject !== card.credentialSubject.id) return c.json({ error: "conflict" }, 409);
    } else {
      store.insertCard({
        serial,
        issuer: card.issuer,
        subject: card.credentialSubject.id,
        validFrom: card.validFrom,
        validUntil: card.validUntil,
        registeredAt: now().toISOString(),
      });
    }
    const status = await signStatus({ serial, status: "valid" }, key, now());
    return c.json(status, existing ? 200 : 201);
  });

  // Status lookup: public, signed, never cached by us.
  app.get("/v1/cards/:serial/status", async (c) => {
    const serial = c.req.param("serial");
    if (!/^[0-9A-HJKMNP-TV-Z]{20}$/.test(serial)) return c.json({ error: "bad_request" }, 400);
    const row = store.getCard(serial);
    let status: CardStatus = "unknown";
    if (row) status = row.revokedAt ? "revoked" : "valid";
    return c.json(await signStatus({ serial, status }, key, now()));
  });

  // Revoke: body is a KinletRevocation signed by the issuer.
  app.post("/v1/cards/:serial/revoke", async (c) => {
    if (!limiter.allow(clientKey(c), now().getTime())) return c.json({ error: "rate_limited" }, 429);
    const serial = c.req.param("serial");
    const row = store.getCard(serial);
    if (!row) return c.json({ error: "card_unknown" }, 404);
    let body: unknown;
    try {
      body = await readJson(c);
    } catch {
      return c.json({ error: "bad_request" }, 400);
    }
    const check = await checkRevocation(body, row.issuer);
    if (!check.ok) return c.json({ error: "revocation_invalid", detail: check.detail }, 400);
    if (check.revocation.serial !== serial) return c.json({ error: "revocation_invalid", detail: "serial mismatch" }, 400);
    if (!row.revokedAt) store.revokeCard(serial, now().toISOString(), JSON.stringify(check.revocation));
    return c.json(await signStatus({ serial, status: "revoked" }, key, now()));
  });

  // Append an activity event: signed by the agent, chained to the previous one.
  app.post("/v1/cards/:serial/events", async (c) => {
    if (!limiter.allow(clientKey(c), now().getTime())) return c.json({ error: "rate_limited" }, 429);
    const serial = c.req.param("serial");
    const row = store.getCard(serial);
    if (!row) return c.json({ error: "card_unknown" }, 404);
    let body: unknown;
    try {
      body = await readJson(c);
    } catch {
      return c.json({ error: "bad_request" }, 400);
    }
    const last = store.lastEvent(serial);
    const expected = { agentDid: row.subject, serial, seq: last ? last.seq + 1 : 0, prev: last ? last.hash : GENESIS_HASH };
    const check = await checkEvent(body, expected);
    if (!check.ok) return c.json({ error: "event_invalid", detail: check.detail, expectedSeq: expected.seq, expectedPrev: expected.prev }, 400);
    store.insertEvent({ serial, seq: check.event.seq, hash: check.hash, json: JSON.stringify(check.event) });
    return c.json({ ok: true, seq: check.event.seq, hash: check.hash }, 201);
  });

  /** Verifies the Kinlet-Owner-Proof header and returns the issuer DID, or null. */
  const ownerFromProof = async (c: { req: { raw: Request } }): Promise<string | null> => {
    const h = c.req.raw.headers.get("kinlet-owner-proof");
    if (!h) return null;
    let raw: unknown;
    try {
      raw = JSON.parse(Buffer.from(h, "base64url").toString("utf8"));
    } catch {
      return null;
    }
    const parsed = OwnerProofSchema.safeParse(raw);
    if (!parsed.success) return null;
    const age = now().getTime() - Date.parse(parsed.data.at);
    if (age > OWNER_PROOF_MAX_AGE_MS || age < -OWNER_PROOF_MAX_AGE_MS) return null;
    const ok = await verifyDocument(parsed.data, parsed.data.issuer);
    return ok.ok ? parsed.data.issuer : null;
  };

  // The person reads their own cards' events.
  app.get("/v1/cards/:serial/events", async (c) => {
    const serial = c.req.param("serial");
    const row = store.getCard(serial);
    if (!row) return c.json({ error: "card_unknown" }, 404);
    const owner = await ownerFromProof(c);
    if (owner !== row.issuer) return c.json({ error: "unauthorized" }, 401);
    const from = Number(c.req.query("from") ?? "0");
    const events = store.events(serial, Number.isFinite(from) ? from : 0).map((e) => JSON.parse(e.json) as unknown);
    return c.json({ serial, events });
  });

  // The person lists their cards (serials and status only; the directory holds nothing else).
  app.get("/v1/issuers/:did/cards", async (c) => {
    const did = c.req.param("did");
    const owner = await ownerFromProof(c);
    if (owner !== did) return c.json({ error: "unauthorized" }, 401);
    const cards = store.cardsForIssuer(did).map((r) => ({
      serial: r.serial,
      subject: r.subject,
      validFrom: r.validFrom,
      validUntil: r.validUntil,
      registeredAt: r.registeredAt,
      status: r.revokedAt ? "revoked" : "valid",
      revokedAt: r.revokedAt,
    }));
    return c.json({ issuer: did, cards });
  });

  // ---- Approval relay ----
  // The agent runtime posts a request for consent; the person's app fetches pending ones, signs a
  // token (or denies), and posts the answer; the runtime polls for it. The directory never signs
  // anything here, so it cannot approve on the person's behalf.

  const ApprovalRequestSchema = z
    .object({
      type: z.literal("KinletApprovalRequest"),
      card: z.string().regex(/^[0-9A-HJKMNP-TV-Z]{20}$/),
      target: z.string().url(),
      action: z.record(z.unknown()),
      nonce: z.string().regex(/^[A-Za-z0-9_-]{22,64}$/),
      at: z.string().datetime({ offset: false }),
      proof: ProofSchema,
    })
    .strict();

  app.post("/v1/cards/:serial/approvals", async (c) => {
    if (!limiter.allow(clientKey(c), now().getTime())) return c.json({ error: "rate_limited" }, 429);
    const serial = c.req.param("serial");
    const row = store.getCard(serial);
    if (!row) return c.json({ error: "card_unknown" }, 404);
    if (row.revokedAt) return c.json({ error: "card_revoked" }, 403);
    let body: unknown;
    try {
      body = await readJson(c);
    } catch {
      return c.json({ error: "bad_request" }, 400);
    }
    const parsed = ApprovalRequestSchema.safeParse(body);
    if (!parsed.success || parsed.data.card !== serial) return c.json({ error: "bad_request" }, 400);
    const age = now().getTime() - Date.parse(parsed.data.at);
    if (age > OWNER_PROOF_MAX_AGE_MS || age < -OWNER_PROOF_MAX_AGE_MS) return c.json({ error: "bad_request", detail: "stale" }, 400);
    const ok = await verifyDocument(parsed.data, row.subject);
    if (!ok.ok) return c.json({ error: "bad_request", detail: "not signed by the card's agent" }, 400);
    const id = "apr_" + parsed.data.nonce;
    if (store.getApproval(id)) return c.json({ error: "conflict" }, 409);
    store.insertApproval({ id, serial, issuer: row.issuer, requestJson: JSON.stringify(parsed.data), createdAt: now().toISOString(), status: "pending", token: null });
    return c.json({ id, status: "pending" }, 201);
  });

  app.get("/v1/issuers/:did/approvals", async (c) => {
    const did = c.req.param("did");
    const owner = await ownerFromProof(c);
    if (owner !== did) return c.json({ error: "unauthorized" }, 401);
    const pending = store.pendingApprovals(did).map((a) => ({ id: a.id, serial: a.serial, createdAt: a.createdAt, request: JSON.parse(a.requestJson) as unknown }));
    return c.json({ issuer: did, pending });
  });

  app.post("/v1/approvals/:id/answer", async (c) => {
    const id = c.req.param("id");
    const a = store.getApproval(id);
    if (!a) return c.json({ error: "not_found" }, 404);
    const owner = await ownerFromProof(c);
    if (owner !== a.issuer) return c.json({ error: "unauthorized" }, 401);
    let body: unknown;
    try {
      body = await readJson(c);
    } catch {
      return c.json({ error: "bad_request" }, 400);
    }
    const parsed = z.object({ decision: z.enum(["approved", "denied"]), token: z.string().max(8192).optional() }).strict().safeParse(body);
    if (!parsed.success) return c.json({ error: "bad_request" }, 400);
    if (parsed.data.decision === "approved" && !parsed.data.token) return c.json({ error: "bad_request", detail: "token required" }, 400);
    if (a.status !== "pending") return c.json({ error: "conflict" }, 409);
    store.resolveApproval(id, parsed.data.decision, parsed.data.decision === "approved" ? (parsed.data.token as string) : null);
    return c.json({ id, status: parsed.data.decision });
  });

  app.get("/v1/approvals/:id", async (c) => {
    const a = store.getApproval(c.req.param("id"));
    if (!a) return c.json({ error: "not_found" }, 404);
    // The token is useless without the agent key and is bound to one nonce, so no auth is needed here.
    return c.json({ id: a.id, status: a.status, token: a.status === "approved" ? a.token : null });
  });

  app.notFound((c) => c.json({ error: "not_found" }, 404));
  app.onError((_err, c) => c.json({ error: "internal" }, 500));

  return app;
}
