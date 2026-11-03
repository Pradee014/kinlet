/**
 * Documents exchanged with a directory: status answers, revocations, activity events.
 * See docs/CARD_FORMAT.md sections 6 to 8.
 */
import { z } from "zod";
import { base64urlEncode, hexEncode, utf8Encode } from "./encoding.js";
import { sha256, type Signer } from "./crypto.js";
import { jcs, ProofSchema, signDocument, verifyDocument, type Signed } from "./proof.js";
import type { ActionSpec } from "./request.js";

const serial = z.string().regex(/^[0-9A-HJKMNP-TV-Z]{20}$/);
const didKey = z.string().regex(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
const rfc3339 = z.string().datetime({ offset: false });
const proofShape = ProofSchema;

// ---- Status ----

export const StatusSchema = z
  .object({
    type: z.literal("KinletStatus"),
    serial,
    status: z.enum(["valid", "revoked", "unknown"]),
    checkedAt: rfc3339,
    directory: didKey,
    proof: proofShape,
  })
  .strict();
export type StatusDoc = z.infer<typeof StatusSchema>;
export type CardStatus = StatusDoc["status"];

export async function signStatus(input: { serial: string; status: CardStatus }, directoryKey: Signer, now: Date = new Date()): Promise<StatusDoc> {
  const doc = { type: "KinletStatus" as const, serial: input.serial, status: input.status, checkedAt: now.toISOString(), directory: directoryKey.did };
  return (await signDocument(doc, directoryKey, { created: now })) as StatusDoc;
}

export type StatusCheck = { ok: true; status: StatusDoc } | { ok: false; reason: "directory_unreachable"; detail: string };

/** Verifies a status answer: shape, signer, freshness. */
export async function checkStatusDoc(raw: unknown, expected: { serial: string; directoryDid: string }, now: Date = new Date(), maxAgeMs = 60_000): Promise<StatusCheck> {
  const parsed = StatusSchema.safeParse(raw);
  if (!parsed.success) return { ok: false, reason: "directory_unreachable", detail: "status malformed" };
  const s = parsed.data;
  if (s.serial !== expected.serial) return { ok: false, reason: "directory_unreachable", detail: "status for a different serial" };
  if (s.directory !== expected.directoryDid) return { ok: false, reason: "directory_unreachable", detail: "status from an unexpected directory key" };
  const age = now.getTime() - Date.parse(s.checkedAt);
  if (age > maxAgeMs || age < -60_000) return { ok: false, reason: "directory_unreachable", detail: "status is stale" };
  const proof = await verifyDocument(s, expected.directoryDid);
  if (!proof.ok) return { ok: false, reason: "directory_unreachable", detail: "status signature invalid" };
  return { ok: true, status: s };
}

// ---- Revocation ----

export const RevocationSchema = z
  .object({
    type: z.literal("KinletRevocation"),
    serial,
    revokedAt: rfc3339,
    reason: z.string().max(200).optional(),
    proof: proofShape,
  })
  .strict();
export type RevocationDoc = z.infer<typeof RevocationSchema>;

export async function signRevocation(input: { serial: string; reason?: string }, issuer: Signer, now: Date = new Date()): Promise<RevocationDoc> {
  const doc: { type: "KinletRevocation"; serial: string; revokedAt: string; reason?: string } = {
    type: "KinletRevocation",
    serial: input.serial,
    revokedAt: now.toISOString(),
  };
  if (input.reason !== undefined) doc.reason = input.reason;
  return (await signDocument(doc, issuer, { created: now })) as RevocationDoc;
}

export async function checkRevocation(raw: unknown, issuerDid: string): Promise<{ ok: true; revocation: RevocationDoc } | { ok: false; detail: string }> {
  const parsed = RevocationSchema.safeParse(raw);
  if (!parsed.success) return { ok: false, detail: "malformed" };
  const proof = await verifyDocument(parsed.data, issuerDid);
  if (!proof.ok) return { ok: false, detail: proof.reason };
  return { ok: true, revocation: parsed.data };
}

// ---- Activity events ----

export const GENESIS_HASH = "0".repeat(64);

export const EventSchema = z
  .object({
    type: z.literal("KinletEvent"),
    serial,
    seq: z.number().int().nonnegative(),
    prev: z.string().regex(/^[0-9a-f]{64}$/),
    at: rfc3339,
    target: z.string().url(),
    action: z.record(z.unknown()),
    outcome: z.string().regex(/^(ok|error|refused:[a-z_]+)$/),
    proof: proofShape,
  })
  .strict();
export type EventDoc = z.infer<typeof EventSchema>;
export type UnsignedEvent = Omit<EventDoc, "proof">;

/** Hash of a signed event's canonical JSON, used as the next event's `prev`. */
export async function eventHash(event: EventDoc): Promise<string> {
  return hexEncode(await sha256(utf8Encode(jcs(event))));
}

export async function signEvent(
  input: { serial: string; seq: number; prev: string; target: string; action: ActionSpec; outcome: string },
  agent: Signer,
  now: Date = new Date(),
): Promise<EventDoc> {
  const doc: UnsignedEvent = {
    type: "KinletEvent",
    serial: input.serial,
    seq: input.seq,
    prev: input.prev,
    at: now.toISOString(),
    target: input.target,
    action: input.action,
    outcome: input.outcome,
  };
  return (await signDocument(doc, agent, { created: now })) as Signed<UnsignedEvent> as EventDoc;
}

export async function checkEvent(
  raw: unknown,
  expected: { agentDid: string; serial: string; seq: number; prev: string },
): Promise<{ ok: true; event: EventDoc; hash: string } | { ok: false; detail: string }> {
  const parsed = EventSchema.safeParse(raw);
  if (!parsed.success) return { ok: false, detail: "malformed" };
  const e = parsed.data;
  if (e.serial !== expected.serial) return { ok: false, detail: "wrong serial" };
  if (e.seq !== expected.seq) return { ok: false, detail: `expected seq ${expected.seq}` };
  if (e.prev !== expected.prev) return { ok: false, detail: "chain broken" };
  const proof = await verifyDocument(e, expected.agentDid);
  if (!proof.ok) return { ok: false, detail: proof.reason };
  return { ok: true, event: e, hash: await eventHash(e) };
}

// ---- Owner proof (person authenticating to the directory to read their own data) ----

/** Header value proving control of an issuer DID: base64url of a signed, time-stamped statement. */
export async function createOwnerProof(issuer: Signer, now: Date = new Date()): Promise<string> {
  const signed = await signDocument({ type: "KinletOwnerProof" as const, issuer: issuer.did, at: now.toISOString() }, issuer, { purpose: "authentication", created: now });
  const json = JSON.stringify(signed);
  const bytes = utf8Encode(json);
  return base64urlEncode(bytes);
}
