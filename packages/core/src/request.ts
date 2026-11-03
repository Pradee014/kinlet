/**
 * Signed requests: a strict profile of HTTP Message Signatures (RFC 9421) with Content-Digest
 * (RFC 9530). See docs/CARD_FORMAT.md section 4.
 */
import { base64Decode, base64Encode, base64urlDecode, base64urlEncode, utf8Decode, utf8Encode } from "./encoding.js";
import { publicKeyFromDidKey, randomBytes, sha256, verify, type Signer } from "./crypto.js";
import { jcs } from "./proof.js";
import type { Card } from "./card.js";

export const SIGNATURE_TAG = "kinlet-v1";
export const SIGNATURE_LABEL = "kinlet";
export const COVERED_COMPONENTS = ["@method", "@target-uri", "content-digest", "kinlet-action"] as const;
export const MAX_REQUEST_WINDOW_S = 300;
export const CLOCK_SKEW_S = 60;

export const HEADER_CARD = "kinlet-card";
export const HEADER_ACTION = "kinlet-action";
export const HEADER_APPROVAL = "kinlet-approval";
export const HEADER_CONTENT_DIGEST = "content-digest";
export const HEADER_SIGNATURE_INPUT = "signature-input";
export const HEADER_SIGNATURE = "signature";

export interface ActionSpec {
  type: string;
  amount?: number;
  currency?: string;
  ref?: string;
  [key: string]: unknown;
}

export interface SignatureParams {
  created: number;
  expires: number;
  nonce: string;
  keyid: string;
  alg: "ed25519";
  tag: typeof SIGNATURE_TAG;
}

function bodyBytes(body: Uint8Array | string | undefined): Uint8Array {
  if (body === undefined) return new Uint8Array(0);
  return typeof body === "string" ? utf8Encode(body) : body;
}

export async function contentDigest(body: Uint8Array | string | undefined): Promise<string> {
  const digest = await sha256(bodyBytes(body));
  return `sha-256=:${base64Encode(digest)}:`;
}

/** The target URI as RFC 9421 defines it: full URL, no fragment. */
export function targetUri(url: string): string {
  const u = new URL(url);
  u.hash = "";
  return u.toString();
}

/** Target without query string, used for approval binding. */
export function targetForApproval(url: string): string {
  const u = new URL(url);
  u.hash = "";
  u.search = "";
  return u.toString();
}

export function formatSignatureParams(p: SignatureParams): string {
  const list = COVERED_COMPONENTS.map((c) => `"${c}"`).join(" ");
  return `(${list});created=${p.created};expires=${p.expires};nonce="${p.nonce}";keyid="${p.keyid}";alg="${p.alg}";tag="${p.tag}"`;
}

export function buildSignatureBase(input: { method: string; url: string; contentDigest: string; action: string; params: SignatureParams }): string {
  const lines = [
    `"@method": ${input.method.toUpperCase()}`,
    `"@target-uri": ${targetUri(input.url)}`,
    `"content-digest": ${input.contentDigest}`,
    `"kinlet-action": ${input.action}`,
    `"@signature-params": ${formatSignatureParams(input.params)}`,
  ];
  return lines.join("\n");
}

export function newNonce(): string {
  return base64urlEncode(randomBytes(18)); // 24 chars
}

export interface SignRequestInput {
  agent: Signer;
  card: Card;
  method: string;
  url: string;
  body?: Uint8Array | string;
  action: ActionSpec;
  /** Pre-chosen nonce (required when an approval token was issued for it). */
  nonce?: string;
  /** base64url-encoded approval token JSON, if the action needs one. */
  approval?: string;
  now?: Date;
}

export interface SignedRequest {
  headers: Record<string, string>;
  nonce: string;
  signatureBase: string;
}

/** Produces the headers for a signed request. The caller sends the request with its own HTTP client. */
export async function signRequest(input: SignRequestInput): Promise<SignedRequest> {
  if (input.agent.did !== input.card.credentialSubject.id) throw new Error("agent key does not match the card's subject");
  const now = Math.floor((input.now ?? new Date()).getTime() / 1000);
  const params: SignatureParams = {
    created: now,
    expires: now + MAX_REQUEST_WINDOW_S,
    nonce: input.nonce ?? newNonce(),
    keyid: input.agent.did,
    alg: "ed25519",
    tag: SIGNATURE_TAG,
  };
  const digest = await contentDigest(input.body);
  const actionJson = jcs(input.action);
  const base = buildSignatureBase({ method: input.method, url: input.url, contentDigest: digest, action: actionJson, params });
  const sig = await input.agent.sign(utf8Encode(base));
  const headers: Record<string, string> = {
    [HEADER_CARD]: base64urlEncode(utf8Encode(JSON.stringify(input.card))),
    [HEADER_ACTION]: actionJson,
    [HEADER_CONTENT_DIGEST]: digest,
    [HEADER_SIGNATURE_INPUT]: `${SIGNATURE_LABEL}=${formatSignatureParams(params)}`,
    [HEADER_SIGNATURE]: `${SIGNATURE_LABEL}=:${base64Encode(sig)}:`,
  };
  if (input.approval) headers[HEADER_APPROVAL] = input.approval;
  return { headers, nonce: params.nonce, signatureBase: base };
}

export type RequestReason =
  | "request_signature_invalid"
  | "request_expired"
  | "card_malformed";

export interface ParsedRequest {
  card: unknown;
  action: ActionSpec;
  actionJson: string;
  params: SignatureParams;
  approval?: string;
  signatureBase: string;
}

const SIG_INPUT_RE = new RegExp(
  `^${SIGNATURE_LABEL}=\\(("@method" "@target-uri" "content-digest" "kinlet-action")\\);created=(\\d{1,12});expires=(\\d{1,12});nonce="([A-Za-z0-9_-]{22,64})";keyid="(did:key:z[1-9A-HJ-NP-Za-km-z]{40,60})";alg="ed25519";tag="${SIGNATURE_TAG}"$`,
);
const SIG_RE = new RegExp(`^${SIGNATURE_LABEL}=:([A-Za-z0-9+/]{86}==):$`);

function header(headers: Record<string, string | undefined>, name: string): string | undefined {
  // Case-insensitive lookup without allocating a new map per call.
  for (const [k, v] of Object.entries(headers)) if (k.toLowerCase() === name) return v;
  return undefined;
}

export type ParseResult = { ok: true; parsed: ParsedRequest } | { ok: false; reason: RequestReason; detail?: string };

/**
 * Parses the Kinlet headers and rebuilds the signature base. Does not verify anything yet;
 * verifyParsedRequest does, once the card has been checked.
 */
export async function parseRequest(input: {
  method: string;
  url: string;
  headers: Record<string, string | undefined>;
  body?: Uint8Array | string;
}): Promise<ParseResult> {
  const cardHeader = header(input.headers, HEADER_CARD);
  const actionJson = header(input.headers, HEADER_ACTION);
  const digest = header(input.headers, HEADER_CONTENT_DIGEST);
  const sigInput = header(input.headers, HEADER_SIGNATURE_INPUT);
  const sig = header(input.headers, HEADER_SIGNATURE);
  const approval = header(input.headers, HEADER_APPROVAL);
  if (!cardHeader || !actionJson || !digest || !sigInput || !sig) return { ok: false, reason: "request_signature_invalid", detail: "missing headers" };

  let card: unknown;
  try {
    card = JSON.parse(utf8Decode(base64urlDecode(cardHeader)));
  } catch {
    return { ok: false, reason: "card_malformed", detail: "card header is not base64url JSON" };
  }

  let action: ActionSpec;
  try {
    const parsedAction: unknown = JSON.parse(actionJson);
    if (!parsedAction || typeof parsedAction !== "object" || Array.isArray(parsedAction)) throw new Error();
    if (jcs(parsedAction) !== actionJson) return { ok: false, reason: "request_signature_invalid", detail: "action header is not canonical JSON" };
    action = parsedAction as ActionSpec;
    if (typeof action.type !== "string") throw new Error();
  } catch {
    return { ok: false, reason: "request_signature_invalid", detail: "action header malformed" };
  }

  const m = SIG_INPUT_RE.exec(sigInput);
  if (!m) return { ok: false, reason: "request_signature_invalid", detail: "signature-input malformed or wrong profile" };
  const params: SignatureParams = {
    created: Number(m[2]),
    expires: Number(m[3]),
    nonce: m[4] as string,
    keyid: m[5] as string,
    alg: "ed25519",
    tag: SIGNATURE_TAG,
  };
  if (!SIG_RE.test(sig)) return { ok: false, reason: "request_signature_invalid", detail: "signature malformed" };

  const expectedDigest = await contentDigest(input.body);
  if (expectedDigest !== digest) return { ok: false, reason: "request_signature_invalid", detail: "content-digest mismatch" };

  const signatureBase = buildSignatureBase({ method: input.method, url: input.url, contentDigest: digest, action: actionJson, params });
  const parsed: ParsedRequest = { card, action, actionJson, params, signatureBase };
  if (approval) parsed.approval = approval;
  return { ok: true, parsed };
}

export type RequestCheck = { ok: true } | { ok: false; reason: RequestReason; detail?: string };

/** Verifies time window and signature of a parsed request against the card's agent key. */
export async function verifyParsedRequest(parsed: ParsedRequest, card: Card, signatureHeader: string, now: Date = new Date()): Promise<RequestCheck> {
  if (parsed.params.keyid !== card.credentialSubject.id) return { ok: false, reason: "request_signature_invalid", detail: "keyid is not the card's agent" };
  const t = Math.floor(now.getTime() / 1000);
  const { created, expires } = parsed.params;
  if (expires - created > MAX_REQUEST_WINDOW_S || expires < created) return { ok: false, reason: "request_expired", detail: "window too long" };
  if (created > t + CLOCK_SKEW_S) return { ok: false, reason: "request_expired", detail: "created in the future" };
  if (expires < t) return { ok: false, reason: "request_expired" };

  const m = SIG_RE.exec(signatureHeader);
  if (!m) return { ok: false, reason: "request_signature_invalid" };
  let sigBytes: Uint8Array;
  let pub: Uint8Array;
  try {
    sigBytes = base64Decode(m[1] as string);
    pub = publicKeyFromDidKey(card.credentialSubject.id);
  } catch {
    return { ok: false, reason: "request_signature_invalid" };
  }
  const good = await verify(pub, utf8Encode(parsed.signatureBase), sigBytes);
  return good ? { ok: true } : { ok: false, reason: "request_signature_invalid" };
}
