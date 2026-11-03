/**
 * The Kinlet agent card: schema, issuance, and structural + signature validation.
 * See docs/CARD_FORMAT.md section 2.
 */
import { z } from "zod";
import { base32CrockfordEncode } from "./encoding.js";
import { publicKeyFromDidKey, randomBytes, type Signer } from "./crypto.js";
import { signDocument, verifyDocument, type Signed } from "./proof.js";

export const CARD_CONTEXT_V1 = "https://kinlet.dev/ns/card/v1";
export const VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2";
export const MAX_CARD_LIFETIME_MS = 90 * 24 * 60 * 60 * 1000;

export const MONETARY_ACTIONS = new Set(["purchase", "subscribe", "book"]);
export const STANDARD_ACTIONS = ["read", "purchase", "subscribe", "cancel", "book", "message", "signin"] as const;

const didKey = z.string().regex(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/, "must be an Ed25519 did:key");
const rfc3339 = z.string().datetime({ offset: false });
const serialRe = /^[0-9A-HJKMNP-TV-Z]{20}$/;

/**
 * An HTTPS origin: scheme + host + optional port, nothing else.
 * Plain http is accepted only for localhost and 127.0.0.1, so the demo can run on one machine.
 */
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);
const httpsOrigin = z.string().refine((s) => {
  try {
    const u = new URL(s);
    const schemeOk = u.protocol === "https:" || (u.protocol === "http:" && LOOPBACK.has(u.hostname));
    return schemeOk && u.origin === s && u.username === "" && u.password === "";
  } catch {
    return false;
  }
}, "must be an https origin with no path");

/** The directory may live under a path (one host serving several things). No query, hash or trailing slash. */
const directoryUrl = z.string().refine((s) => {
  try {
    const u = new URL(s);
    const schemeOk = u.protocol === "https:" || (u.protocol === "http:" && LOOPBACK.has(u.hostname));
    return schemeOk && u.search === "" && u.hash === "" && u.username === "" && u.password === "" && !s.endsWith("/") && (u.href === s || u.href === s + "/");
  } catch {
    return false;
  }
}, "must be an https URL with no query or trailing slash");

const actionName = z.union([z.enum(STANDARD_ACTIONS), z.string().url().startsWith("https://")]);

/** Money is validated as a non-negative finite number with at most 2 decimals. */
const money = z.number().finite().nonnegative().refine((n) => Math.round(n * 100) === n * 100, "at most 2 decimals");

export const PermissionsSchema = z
  .object({
    services: z.array(httpsOrigin).min(1).max(50),
    actions: z.array(actionName).min(1).max(50),
    limits: z
      .object({
        currency: z.string().regex(/^[A-Z]{3}$/),
        perAction: money,
        perDay: money,
      })
      .strict()
      .optional(),
    approval: z
      .object({
        above: money.optional(),
        forActions: z.array(actionName).max(50).optional(),
      })
      .strict()
      .optional(),
  })
  .strict()
  .superRefine((p, ctx) => {
    const monetary = p.actions.some((a) => MONETARY_ACTIONS.has(a));
    if (monetary && !p.limits) ctx.addIssue({ code: "custom", message: "limits are required when actions include a monetary action" });
    if (p.limits && p.limits.perAction > p.limits.perDay) ctx.addIssue({ code: "custom", message: "perAction must not exceed perDay" });
  });

export const CardSchema = z
  .object({
    "@context": z.tuple([z.literal(VC_CONTEXT_V2), z.literal(CARD_CONTEXT_V1)]),
    type: z.tuple([z.literal("VerifiableCredential"), z.literal("KinletAgentCard")]),
    id: z.string().regex(/^urn:kinlet:card:[0-9A-HJKMNP-TV-Z]{20}$/),
    issuer: didKey,
    validFrom: rfc3339,
    validUntil: rfc3339,
    credentialStatus: z
      .object({
        type: z.literal("KinletDirectoryStatus"),
        directory: directoryUrl,
        serial: z.string().regex(serialRe),
      })
      .strict(),
    credentialSubject: z
      .object({
        id: didKey,
        name: z.string().min(1).max(80),
        permissions: PermissionsSchema,
      })
      .strict(),
    proof: z
      .object({
        type: z.literal("DataIntegrityProof"),
        cryptosuite: z.literal("eddsa-jcs-2022"),
        created: rfc3339,
        verificationMethod: z.string(),
        proofPurpose: z.literal("assertionMethod"),
        proofValue: z.string().startsWith("z"),
      })
      .strict(),
  })
  .strict()
  .superRefine((c, ctx) => {
    if (c.id !== "urn:kinlet:card:" + c.credentialStatus.serial) ctx.addIssue({ code: "custom", message: "id and credentialStatus.serial disagree" });
    const from = Date.parse(c.validFrom);
    const until = Date.parse(c.validUntil);
    if (!(until > from)) ctx.addIssue({ code: "custom", message: "validUntil must be after validFrom" });
    if (until - from > MAX_CARD_LIFETIME_MS) ctx.addIssue({ code: "custom", message: "card lifetime exceeds 90 days" });
    if (c.issuer === c.credentialSubject.id) ctx.addIssue({ code: "custom", message: "issuer and agent must be different keys" });
  });

export type Permissions = z.infer<typeof PermissionsSchema>;
export type Card = z.infer<typeof CardSchema>;
export type UnsignedCard = Omit<Card, "proof">;

export function newSerial(): string {
  // 100 bits of randomness -> 20 Crockford base32 characters.
  const bytes = randomBytes(13);
  return base32CrockfordEncode(bytes).slice(0, 20);
}

export interface IssueCardInput {
  issuer: Signer;
  agentDid: string;
  name: string;
  permissions: Permissions;
  directory: string;
  validFrom?: Date;
  validUntil?: Date;
}

/** Builds and signs a card. Throws if the result would not validate. */
export async function issueCard(input: IssueCardInput): Promise<Card> {
  publicKeyFromDidKey(input.agentDid); // throws if not an Ed25519 did:key
  const serial = newSerial();
  const validFrom = input.validFrom ?? new Date();
  const validUntil = input.validUntil ?? new Date(validFrom.getTime() + 30 * 24 * 60 * 60 * 1000);
  const unsigned: UnsignedCard = {
    "@context": [VC_CONTEXT_V2, CARD_CONTEXT_V1],
    type: ["VerifiableCredential", "KinletAgentCard"],
    id: "urn:kinlet:card:" + serial,
    issuer: input.issuer.did,
    validFrom: validFrom.toISOString(),
    validUntil: validUntil.toISOString(),
    credentialStatus: { type: "KinletDirectoryStatus", directory: input.directory, serial },
    credentialSubject: { id: input.agentDid, name: input.name, permissions: input.permissions },
  };
  const signed = (await signDocument(unsigned, input.issuer, { created: validFrom })) as Signed<UnsignedCard>;
  const parsed = CardSchema.safeParse(signed);
  if (!parsed.success) throw new Error("issued card failed validation: " + parsed.error.issues.map((i) => i.message).join("; "));
  return parsed.data;
}

export type CardCheck =
  | { ok: true; card: Card }
  | { ok: false; reason: "card_malformed" | "card_signature_invalid" | "card_expired" | "card_not_yet_valid"; detail?: string };

/**
 * Structural validation, signature check, and time-window check. Does NOT check revocation;
 * that needs the directory (see verify.ts).
 */
export async function checkCard(input: unknown, now: Date = new Date()): Promise<CardCheck> {
  const parsed = CardSchema.safeParse(input);
  if (!parsed.success) {
    return { ok: false, reason: "card_malformed", detail: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ") };
  }
  const card = parsed.data;
  const proofCheck = await verifyDocument(card, card.issuer);
  if (!proofCheck.ok) return { ok: false, reason: "card_signature_invalid", detail: proofCheck.reason };
  const t = now.getTime();
  if (t < Date.parse(card.validFrom)) return { ok: false, reason: "card_not_yet_valid" };
  if (t >= Date.parse(card.validUntil)) return { ok: false, reason: "card_expired" };
  return { ok: true, card };
}

/** Integer minor units (cents) for exact comparisons. */
export function toMinorUnits(amount: number): number {
  return Math.round(amount * 100);
}
