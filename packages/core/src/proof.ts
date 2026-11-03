/**
 * Data Integrity proofs with the eddsa-jcs-2022 cryptosuite:
 * JSON Canonicalization Scheme (RFC 8785) + SHA-256 + Ed25519.
 * Used for cards, approvals, revocations, status answers and events.
 */
import { z } from "zod";
import canonicalizeImport from "canonicalize";
import { base58btcDecode, base58btcEncode, concatBytes, utf8Encode } from "./encoding.js";
import { publicKeyFromDidKey, sha256, verificationMethodForDid, verify, type Signer } from "./crypto.js";

// `canonicalize` ships CommonJS; normalise the import shape.
const canonicalize: (v: unknown) => string | undefined =
  (canonicalizeImport as unknown as { default?: (v: unknown) => string | undefined }).default ??
  (canonicalizeImport as unknown as (v: unknown) => string | undefined);

export function jcs(value: unknown): string {
  const out = canonicalize(value);
  if (out === undefined) throw new Error("value cannot be canonicalized");
  return out;
}

export interface DataIntegrityProof {
  type: "DataIntegrityProof";
  cryptosuite: "eddsa-jcs-2022";
  created: string;
  verificationMethod: string;
  proofPurpose: "assertionMethod" | "authentication";
  proofValue: string;
}

export type Signed<T extends object> = T & { proof: DataIntegrityProof };

function rejectIfHasProof(doc: object): void {
  if ("proof" in doc) throw new Error("document already carries a proof");
}

async function hashesFor(doc: object, proofOptions: Omit<DataIntegrityProof, "proofValue">): Promise<Uint8Array> {
  const docHash = await sha256(utf8Encode(jcs(doc)));
  const optionsHash = await sha256(utf8Encode(jcs(proofOptions)));
  return concatBytes(optionsHash, docHash);
}

export async function signDocument<T extends object>(
  doc: T,
  signer: Signer,
  opts: { purpose?: DataIntegrityProof["proofPurpose"]; created?: Date } = {},
): Promise<Signed<T>> {
  rejectIfHasProof(doc);
  const options: Omit<DataIntegrityProof, "proofValue"> = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created: (opts.created ?? new Date()).toISOString(),
    verificationMethod: verificationMethodForDid(signer.did),
    proofPurpose: opts.purpose ?? "assertionMethod",
  };
  const toSign = await hashesFor(doc, options);
  const sig = await signer.sign(toSign);
  return { ...doc, proof: { ...options, proofValue: "z" + base58btcEncode(sig) } };
}

export type ProofCheck = { ok: true; signerDid: string } | { ok: false; reason: string };

/**
 * Verifies a proof against an expected signer DID. The verificationMethod inside the proof is
 * checked to belong to that DID, so a document cannot be re-signed by a different key and still pass.
 */
export async function verifyDocument(signed: object, expectedSignerDid: string): Promise<ProofCheck> {
  const { proof, ...doc } = signed as { proof?: unknown };
  if (!proof || typeof proof !== "object") return { ok: false, reason: "proof_missing" };
  const p = proof as Partial<DataIntegrityProof>;
  if (p.type !== "DataIntegrityProof" || p.cryptosuite !== "eddsa-jcs-2022") return { ok: false, reason: "proof_unsupported" };
  if (typeof p.created !== "string" || typeof p.verificationMethod !== "string" || typeof p.proofValue !== "string") {
    return { ok: false, reason: "proof_malformed" };
  }
  if (p.proofPurpose !== "assertionMethod" && p.proofPurpose !== "authentication") return { ok: false, reason: "proof_malformed" };
  if (p.verificationMethod !== verificationMethodForDid(expectedSignerDid)) return { ok: false, reason: "proof_wrong_signer" };
  if (!p.proofValue.startsWith("z")) return { ok: false, reason: "proof_malformed" };

  let publicKey: Uint8Array;
  let signature: Uint8Array;
  try {
    publicKey = publicKeyFromDidKey(expectedSignerDid);
    signature = base58btcDecode(p.proofValue.slice(1));
  } catch {
    return { ok: false, reason: "proof_malformed" };
  }
  const { proofValue: _omit, ...options } = p as DataIntegrityProof;
  void _omit;
  const toVerify = await hashesFor(doc, options);
  const good = await verify(publicKey, toVerify, signature);
  return good ? { ok: true, signerDid: expectedSignerDid } : { ok: false, reason: "proof_invalid" };
}

export const ProofSchema = z
  .object({
    type: z.literal("DataIntegrityProof"),
    cryptosuite: z.literal("eddsa-jcs-2022"),
    created: z.string().datetime({ offset: false }),
    verificationMethod: z.string(),
    proofPurpose: z.enum(["assertionMethod", "authentication"]),
    proofValue: z.string().startsWith("z"),
  })
  .strict();
