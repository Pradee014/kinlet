/**
 * The verifier a service runs on every incoming agent request. One call, one answer, one reason code.
 * Order: parse, card, request signature, replay, scope, limits, approval, directory status.
 * Every check is mandatory; there is no lenient mode.
 */
import { checkCard, MONETARY_ACTIONS, toMinorUnits, type Card } from "./card.js";
import { verifyApproval } from "./approval.js";
import { checkStatusDoc } from "./directory.js";
import { CLOCK_SKEW_S, HEADER_SIGNATURE, parseRequest, verifyParsedRequest, type ActionSpec } from "./request.js";

const CLOCK_SKEW_MS = CLOCK_SKEW_S * 1000;

export type ReasonCode =
  | "card_signature_invalid"
  | "card_expired"
  | "card_not_yet_valid"
  | "card_revoked"
  | "card_unknown"
  | "directory_unreachable"
  | "request_signature_invalid"
  | "request_expired"
  | "request_replayed"
  | "service_not_allowed"
  | "action_not_allowed"
  | "limit_exceeded"
  | "approval_required"
  | "approval_invalid"
  | "card_malformed";

export interface DirectoryClient {
  /** Returns the directory's signing DID (from /.well-known/kinlet.json). May cache. */
  directoryDid(directoryUrl: string): Promise<string>;
  /** Returns the raw status document for a serial. Throws on network failure. */
  status(directoryUrl: string, serial: string): Promise<unknown>;
}

export interface NonceStore {
  /**
   * Records the nonce; returns true if it was already present. Entries may be dropped once
   * `nowMs` passes `expiresAtMs` plus the clock-skew allowance. `nowMs` is the verifier's clock.
   */
  seen(nonce: string, expiresAtMs: number, nowMs: number): Promise<boolean>;
}

export interface SpendLedger {
  /** Minor units already spent for this serial in the current UTC day, in the given currency. */
  spentToday(serial: string, currency: string, now: Date): Promise<number>;
  /** Records a successful monetary action. Called by the service after it completes the action. */
  record(serial: string, currency: string, minorUnits: number, now: Date): Promise<void>;
}

export interface VerifierDeps {
  directory: DirectoryClient;
  nonces: NonceStore;
  ledger: SpendLedger;
  now?: () => Date;
  /** Origin of this service, e.g. https://shop.example.com. Must appear in the card's services. */
  serviceOrigin: string;
}

export interface IncomingRequest {
  method: string;
  url: string;
  headers: Record<string, string | undefined>;
  body?: Uint8Array | string;
}

export type VerifyResult =
  | { ok: true; card: Card; serial: string; action: ActionSpec; nonce: string; amountMinor?: number; currency?: string }
  | { ok: false; reason: ReasonCode; detail?: string };

function fail(reason: ReasonCode, detail?: string): VerifyResult {
  return detail === undefined ? { ok: false, reason } : { ok: false, reason, detail };
}

export async function verifyIncomingRequest(deps: VerifierDeps, req: IncomingRequest): Promise<VerifyResult> {
  const now = deps.now ? deps.now() : new Date();

  // 1. Parse headers and rebuild the signature base.
  const parsed = await parseRequest(req);
  if (!parsed.ok) return fail(parsed.reason, parsed.detail);
  const p = parsed.parsed;

  // 2. Card: structure, issuer signature, time window.
  const cardCheck = await checkCard(p.card, now);
  if (!cardCheck.ok) return fail(cardCheck.reason, cardCheck.detail);
  const card = cardCheck.card;
  const serial = card.credentialStatus.serial;

  // 3. Request: signed by the card's agent, inside the time window.
  const sigHeader = Object.entries(req.headers).find(([k]) => k.toLowerCase() === HEADER_SIGNATURE)?.[1] ?? "";
  const reqCheck = await verifyParsedRequest(p, card, sigHeader, now);
  if (!reqCheck.ok) return fail(reqCheck.reason, reqCheck.detail);

  // 4. Replay.
  if (await deps.nonces.seen(p.params.nonce, p.params.expires * 1000, now.getTime())) return fail("request_replayed");

  // 5. Scope: this service, this action.
  let origin: string;
  try {
    origin = new URL(req.url).origin;
  } catch {
    return fail("request_signature_invalid", "bad url");
  }
  if (origin !== deps.serviceOrigin) return fail("service_not_allowed", "request url is not this service");
  const perms = card.credentialSubject.permissions;
  if (!perms.services.includes(origin)) return fail("service_not_allowed");
  if (!perms.actions.includes(p.action.type)) return fail("action_not_allowed");

  // 6. Limits for monetary actions.
  let amountMinor: number | undefined;
  let currency: string | undefined;
  if (MONETARY_ACTIONS.has(p.action.type)) {
    if (!perms.limits) return fail("card_malformed", "monetary action without limits");
    if (typeof p.action.amount !== "number" || !Number.isFinite(p.action.amount) || p.action.amount < 0) return fail("limit_exceeded", "amount missing");
    if (p.action.currency !== perms.limits.currency) return fail("limit_exceeded", "currency not allowed");
    amountMinor = toMinorUnits(p.action.amount);
    currency = perms.limits.currency;
    if (amountMinor > toMinorUnits(perms.limits.perAction)) return fail("limit_exceeded", "per-action limit");
    const spent = await deps.ledger.spentToday(serial, currency, now);
    if (spent + amountMinor > toMinorUnits(perms.limits.perDay)) return fail("limit_exceeded", "daily limit");
  }

  // 7. Approval.
  const needsApproval =
    (perms.approval?.forActions?.includes(p.action.type) ?? false) ||
    (perms.approval?.above !== undefined && amountMinor !== undefined && amountMinor >= toMinorUnits(perms.approval.above));
  if (needsApproval) {
    if (!p.approval) return fail("approval_required");
    const a = await verifyApproval(p.approval, { card, url: req.url, action: p.action, nonce: p.params.nonce }, now);
    if (!a.ok) return fail("approval_invalid", a.detail);
  }

  // 8. Directory status, fail closed.
  let raw: unknown;
  let directoryDid: string;
  try {
    directoryDid = await deps.directory.directoryDid(card.credentialStatus.directory);
    raw = await deps.directory.status(card.credentialStatus.directory, serial);
  } catch (e) {
    return fail("directory_unreachable", e instanceof Error ? e.message : "fetch failed");
  }
  const st = await checkStatusDoc(raw, { serial, directoryDid }, now);
  if (!st.ok) return fail(st.reason, st.detail);
  if (st.status.status === "revoked") return fail("card_revoked");
  if (st.status.status === "unknown") return fail("card_unknown");

  const result: VerifyResult = { ok: true, card, serial, action: p.action, nonce: p.params.nonce };
  if (amountMinor !== undefined && currency !== undefined) {
    result.amountMinor = amountMinor;
    result.currency = currency;
  }
  return result;
}

/** In-memory stores for tests and single-process services. Not for multi-instance deployments. */
export class MemoryNonceStore implements NonceStore {
  private readonly map = new Map<string, number>();
  async seen(nonce: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
    for (const [k, exp] of this.map) if (exp < nowMs) this.map.delete(k);
    if (this.map.has(nonce)) return true;
    this.map.set(nonce, expiresAtMs + CLOCK_SKEW_MS);
    return false;
  }
}

export class MemorySpendLedger implements SpendLedger {
  private readonly entries: { serial: string; currency: string; minor: number; day: string }[] = [];
  private static day(d: Date): string {
    return d.toISOString().slice(0, 10);
  }
  async spentToday(serial: string, currency: string, now: Date): Promise<number> {
    const day = MemorySpendLedger.day(now);
    return this.entries.filter((e) => e.serial === serial && e.currency === currency && e.day === day).reduce((n, e) => n + e.minor, 0);
  }
  async record(serial: string, currency: string, minorUnits: number, now: Date): Promise<void> {
    this.entries.push({ serial, currency, minor: minorUnits, day: MemorySpendLedger.day(now) });
  }
}

/** A directory client over fetch, with a short cache for the directory DID and a hard timeout. */
export function fetchDirectoryClient(fetchFn: typeof fetch = fetch, timeoutMs = 3000): DirectoryClient {
  const didCache = new Map<string, { did: string; until: number }>();
  const get = async (url: string): Promise<unknown> => {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const res = await fetchFn(url, { signal: ctl.signal, headers: { accept: "application/json" } });
      if (!res.ok) throw new Error(`directory responded ${res.status}`);
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  };
  return {
    async directoryDid(directoryUrl: string): Promise<string> {
      const hit = didCache.get(directoryUrl);
      if (hit && hit.until > Date.now()) return hit.did;
      const doc = (await get(directoryUrl.replace(/\/$/, "") + "/.well-known/kinlet.json")) as { did?: unknown };
      if (typeof doc.did !== "string") throw new Error("well-known document has no did");
      didCache.set(directoryUrl, { did: doc.did, until: Date.now() + 10 * 60_000 });
      return doc.did;
    },
    async status(directoryUrl: string, serial: string): Promise<unknown> {
      return get(directoryUrl.replace(/\/$/, "") + `/v1/cards/${encodeURIComponent(serial)}/status`);
    },
  };
}
