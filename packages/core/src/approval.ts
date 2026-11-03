/**
 * Approval tokens: the person's consent to one specific request, signed by the root key.
 * See docs/CARD_FORMAT.md section 5.
 */
import { z } from "zod";
import { base64urlDecode, base64urlEncode, utf8Decode, utf8Encode } from "./encoding.js";
import type { Signer } from "./crypto.js";
import { jcs, ProofSchema, signDocument, verifyDocument } from "./proof.js";
import type { Card } from "./card.js";
import { targetForApproval, type ActionSpec } from "./request.js";

export const MAX_APPROVAL_LIFETIME_MS = 10 * 60 * 1000;

export const ApprovalSchema = z
  .object({
    type: z.literal("KinletApproval"),
    card: z.string().regex(/^[0-9A-HJKMNP-TV-Z]{20}$/),
    target: z.string().url(),
    action: z.record(z.unknown()).refine((a) => typeof a["type"] === "string", "action.type required"),
    nonce: z.string().regex(/^[A-Za-z0-9_-]{22,64}$/),
    created: z.string().datetime({ offset: false }),
    expires: z.string().datetime({ offset: false }),
    proof: ProofSchema,
  })
  .strict();

export type Approval = z.infer<typeof ApprovalSchema>;

/** What the agent runtime sends to the person's app to ask for consent. */
export interface ApprovalRequest {
  card: string;
  target: string;
  action: ActionSpec;
  nonce: string;
}

export function approvalRequestFor(card: Card, url: string, action: ActionSpec, nonce: string): ApprovalRequest {
  return { card: card.credentialStatus.serial, target: targetForApproval(url), action, nonce };
}

/** Signs an approval with the person's root key. Returns the base64url token for the header. */
export async function createApproval(req: ApprovalRequest, issuer: Signer, now: Date = new Date()): Promise<string> {
  const doc = {
    type: "KinletApproval" as const,
    card: req.card,
    target: req.target,
    action: req.action,
    nonce: req.nonce,
    created: now.toISOString(),
    expires: new Date(now.getTime() + MAX_APPROVAL_LIFETIME_MS).toISOString(),
  };
  const signed = await signDocument(doc, issuer, { purpose: "authentication", created: now });
  return base64urlEncode(utf8Encode(JSON.stringify(signed)));
}

export type ApprovalCheck = { ok: true } | { ok: false; reason: "approval_invalid"; detail: string };

/** Verifies that a token is a valid, unexpired approval of exactly this request by the card's issuer. */
export async function verifyApproval(
  token: string,
  expected: { card: Card; url: string; action: ActionSpec; nonce: string },
  now: Date = new Date(),
): Promise<ApprovalCheck> {
  let raw: unknown;
  try {
    raw = JSON.parse(utf8Decode(base64urlDecode(token)));
  } catch {
    return { ok: false, reason: "approval_invalid", detail: "not base64url JSON" };
  }
  const parsed = ApprovalSchema.safeParse(raw);
  if (!parsed.success) return { ok: false, reason: "approval_invalid", detail: "malformed" };
  const a = parsed.data;
  if (a.card !== expected.card.credentialStatus.serial) return { ok: false, reason: "approval_invalid", detail: "different card" };
  if (a.target !== targetForApproval(expected.url)) return { ok: false, reason: "approval_invalid", detail: "different target" };
  if (jcs(a.action) !== jcs(expected.action)) return { ok: false, reason: "approval_invalid", detail: "different action" };
  if (a.nonce !== expected.nonce) return { ok: false, reason: "approval_invalid", detail: "different nonce" };
  const created = Date.parse(a.created);
  const expires = Date.parse(a.expires);
  if (!(expires > created) || expires - created > MAX_APPROVAL_LIFETIME_MS) return { ok: false, reason: "approval_invalid", detail: "bad lifetime" };
  const t = now.getTime();
  if (t >= expires || t < created - 60_000) return { ok: false, reason: "approval_invalid", detail: "expired" };
  const proof = await verifyDocument(a, expected.card.issuer);
  if (!proof.ok) return { ok: false, reason: "approval_invalid", detail: proof.reason };
  return { ok: true };
}
