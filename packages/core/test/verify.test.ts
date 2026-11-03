import { describe, expect, it } from "vitest";
import {
  approvalRequestFor,
  createApproval,
  generateKeyPair,
  issueCard,
  newNonce,
  signRequest,
  verifyIncomingRequest,
  type ActionSpec,
  type VerifyResult,
} from "../src/index.js";
import { DIRECTORY, makeWorld, SHOP, type World } from "./helpers.js";

const ORDERS = SHOP + "/orders";

async function send(w: World, opts: { action?: ActionSpec; url?: string; method?: string; body?: string; nonce?: string; approval?: string; mutate?: (h: Record<string, string>) => void } = {}): Promise<VerifyResult> {
  const action = opts.action ?? { type: "purchase", amount: 12.5, currency: "USD", ref: "sku-1" };
  const url = opts.url ?? ORDERS;
  const method = opts.method ?? "POST";
  const body = opts.body ?? JSON.stringify({ sku: "sku-1" });
  const signInput: Parameters<typeof signRequest>[0] = { agent: w.agent, card: w.card, method, url, body, action, now: w.now() };
  if (opts.nonce) signInput.nonce = opts.nonce;
  if (opts.approval) signInput.approval = opts.approval;
  const signed = await signRequest(signInput);
  if (opts.mutate) opts.mutate(signed.headers);
  return verifyIncomingRequest(w.deps, { method, url, headers: signed.headers, body });
}

function reason(r: VerifyResult): string {
  return r.ok ? "ok" : r.reason;
}

describe("happy path", () => {
  it("accepts a well-formed purchase inside limits", async () => {
    const w = await makeWorld();
    const r = await send(w);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.amountMinor).toBe(1250);
      expect(r.currency).toBe("USD");
      expect(r.serial).toBe(w.card.credentialStatus.serial);
    }
  });

  it("accepts a non-monetary read with no limits involved", async () => {
    const w = await makeWorld();
    const r = await send(w, { action: { type: "read" }, method: "GET", url: SHOP + "/catalog?q=lamp", body: "" });
    expect(reason(r)).toBe("ok");
  });

  it("accepts an approved action above the threshold", async () => {
    const w = await makeWorld();
    const action: ActionSpec = { type: "purchase", amount: 45, currency: "USD" };
    const nonce = newNonce();
    const approval = await createApproval(approvalRequestFor(w.card, ORDERS, action, nonce), w.person, w.now());
    const r = await send(w, { action, nonce, approval });
    expect(reason(r)).toBe("ok");
  });
});

describe("must refuse", () => {
  it("1. card signature invalid (tampered permissions)", async () => {
    const w = await makeWorld();
    const r = await send(w, {
      mutate: (h) => {
        const card = JSON.parse(Buffer.from(h["kinlet-card"] as string, "base64url").toString());
        card.credentialSubject.permissions.limits.perAction = 99; // still structurally valid (<= perDay)
        h["kinlet-card"] = Buffer.from(JSON.stringify(card)).toString("base64url");
      },
    });
    expect(reason(r)).toBe("card_signature_invalid");
  });

  it("2a. card expired", async () => {
    const w = await makeWorld({ validUntil: new Date("2026-11-04T12:00:00Z") });
    w.setNow(new Date("2026-11-05T12:00:00Z"));
    expect(reason(await send(w))).toBe("card_expired");
  });

  it("2b. card not yet valid", async () => {
    const w = await makeWorld();
    w.setNow(new Date("2026-11-03T11:00:00Z"));
    expect(reason(await send(w))).toBe("card_not_yet_valid");
  });

  it("3a. card revoked", async () => {
    const w = await makeWorld();
    w.statuses.set(w.card.credentialStatus.serial, "revoked");
    expect(reason(await send(w))).toBe("card_revoked");
  });

  it("3b. card unknown to the directory", async () => {
    const w = await makeWorld();
    w.statuses.delete(w.card.credentialStatus.serial);
    expect(reason(await send(w))).toBe("card_unknown");
  });

  it("4a. directory unreachable fails closed", async () => {
    const w = await makeWorld();
    w.deps.directory = {
      directoryDid: async () => w.directoryKey.did,
      status: async () => {
        throw new Error("ECONNREFUSED");
      },
    };
    expect(reason(await send(w))).toBe("directory_unreachable");
  });

  it("4b. status signed by the wrong key is treated as unreachable", async () => {
    const w = await makeWorld();
    const impostor = await generateKeyPair();
    const real = w.deps.directory;
    w.deps.directory = { directoryDid: async () => w.directoryKey.did, status: (u, s) => real.status(u, s) };
    // Replace signer: re-sign statuses with an impostor key.
    const { signStatus } = await import("../src/index.js");
    w.deps.directory.status = async (_u, s) => signStatus({ serial: s, status: "valid" }, impostor, w.now());
    expect(reason(await send(w))).toBe("directory_unreachable");
  });

  it("4c. stale status is rejected", async () => {
    const w = await makeWorld();
    const { signStatus } = await import("../src/index.js");
    w.deps.directory.status = async (_u, s) => signStatus({ serial: s, status: "valid" }, w.directoryKey, new Date(w.now().getTime() - 5 * 60_000));
    expect(reason(await send(w))).toBe("directory_unreachable");
  });

  it("5a. request signed by a different key", async () => {
    const w = await makeWorld();
    const thief = await generateKeyPair();
    const signed = await signRequest({ agent: thief, card: { ...w.card, credentialSubject: { ...w.card.credentialSubject, id: thief.did } }, method: "POST", url: ORDERS, body: "{}", action: { type: "read" }, now: w.now() });
    // Put the real card back so the card signature is fine but keyid/signature are not.
    signed.headers["kinlet-card"] = Buffer.from(JSON.stringify(w.card)).toString("base64url");
    const r = await verifyIncomingRequest(w.deps, { method: "POST", url: ORDERS, headers: signed.headers, body: "{}" });
    expect(reason(r)).toBe("request_signature_invalid");
  });

  it("5b. body tampered after signing", async () => {
    const w = await makeWorld();
    const signed = await signRequest({ agent: w.agent, card: w.card, method: "POST", url: ORDERS, body: '{"sku":"a"}', action: { type: "read" }, now: w.now() });
    const r = await verifyIncomingRequest(w.deps, { method: "POST", url: ORDERS, headers: signed.headers, body: '{"sku":"b"}' });
    expect(reason(r)).toBe("request_signature_invalid");
  });

  it("5c. action header tampered after signing", async () => {
    const w = await makeWorld();
    const r = await send(w, { mutate: (h) => (h["kinlet-action"] = '{"amount":1,"currency":"USD","type":"purchase"}') });
    expect(reason(r)).toBe("request_signature_invalid");
  });

  it("5d. url changed after signing", async () => {
    const w = await makeWorld();
    const signed = await signRequest({ agent: w.agent, card: w.card, method: "POST", url: ORDERS, body: "{}", action: { type: "read" }, now: w.now() });
    const r = await verifyIncomingRequest(w.deps, { method: "POST", url: SHOP + "/orders/other", headers: signed.headers, body: "{}" });
    expect(reason(r)).toBe("request_signature_invalid");
  });

  it("6a. request older than the window", async () => {
    const w = await makeWorld();
    const signed = await signRequest({ agent: w.agent, card: w.card, method: "POST", url: ORDERS, body: "{}", action: { type: "read" }, now: new Date(w.now().getTime() - 10 * 60_000) });
    const r = await verifyIncomingRequest(w.deps, { method: "POST", url: ORDERS, headers: signed.headers, body: "{}" });
    expect(reason(r)).toBe("request_expired");
  });

  it("6b. replayed nonce", async () => {
    const w = await makeWorld();
    const signed = await signRequest({ agent: w.agent, card: w.card, method: "POST", url: ORDERS, body: "{}", action: { type: "read" }, now: w.now() });
    const first = await verifyIncomingRequest(w.deps, { method: "POST", url: ORDERS, headers: signed.headers, body: "{}" });
    const second = await verifyIncomingRequest(w.deps, { method: "POST", url: ORDERS, headers: signed.headers, body: "{}" });
    expect(reason(first)).toBe("ok");
    expect(reason(second)).toBe("request_replayed");
  });

  it("7. service not in the card", async () => {
    const w = await makeWorld();
    w.deps.serviceOrigin = "https://other.example.com";
    const r = await send(w, { url: "https://other.example.com/orders" });
    expect(reason(r)).toBe("service_not_allowed");
  });

  it("8. action not in the card", async () => {
    const w = await makeWorld();
    expect(reason(await send(w, { action: { type: "subscribe", amount: 1, currency: "USD" } }))).toBe("action_not_allowed");
  });

  it("9a. per-action limit exceeded (even with approval)", async () => {
    const w = await makeWorld();
    const action: ActionSpec = { type: "purchase", amount: 50.01, currency: "USD" };
    const nonce = newNonce();
    const approval = await createApproval(approvalRequestFor(w.card, ORDERS, action, nonce), w.person, w.now());
    expect(reason(await send(w, { action, nonce, approval }))).toBe("limit_exceeded");
  });

  it("9b. daily limit exceeded across requests", async () => {
    const w = await makeWorld();
    await w.ledger.record(w.card.credentialStatus.serial, "USD", 9000, w.now());
    expect(reason(await send(w, { action: { type: "purchase", amount: 15, currency: "USD" } }))).toBe("limit_exceeded");
  });

  it("9c. wrong currency", async () => {
    const w = await makeWorld();
    expect(reason(await send(w, { action: { type: "purchase", amount: 1, currency: "EUR" } }))).toBe("limit_exceeded");
  });

  it("10a. approval required above threshold", async () => {
    const w = await makeWorld();
    expect(reason(await send(w, { action: { type: "purchase", amount: 20, currency: "USD" } }))).toBe("approval_required");
  });

  it("10b. approval required for listed action", async () => {
    const w = await makeWorld();
    expect(reason(await send(w, { action: { type: "cancel", ref: "order-9" } }))).toBe("approval_required");
  });

  it("10c. approval signed by the agent key is rejected", async () => {
    const w = await makeWorld();
    const action: ActionSpec = { type: "purchase", amount: 45, currency: "USD" };
    const nonce = newNonce();
    const forged = await createApproval(approvalRequestFor(w.card, ORDERS, action, nonce), w.agent, w.now());
    expect(reason(await send(w, { action, nonce, approval: forged }))).toBe("approval_invalid");
  });

  it("10d. approval for a different amount is rejected", async () => {
    const w = await makeWorld();
    const nonce = newNonce();
    const approval = await createApproval(approvalRequestFor(w.card, ORDERS, { type: "purchase", amount: 21, currency: "USD" }, nonce), w.person, w.now());
    expect(reason(await send(w, { action: { type: "purchase", amount: 45, currency: "USD" }, nonce, approval }))).toBe("approval_invalid");
  });

  it("10e. approval reused with a different nonce is rejected", async () => {
    const w = await makeWorld();
    const action: ActionSpec = { type: "purchase", amount: 45, currency: "USD" };
    const approval = await createApproval(approvalRequestFor(w.card, ORDERS, action, newNonce()), w.person, w.now());
    expect(reason(await send(w, { action, nonce: newNonce(), approval }))).toBe("approval_invalid");
  });

  it("10f. expired approval is rejected", async () => {
    const w = await makeWorld();
    const action: ActionSpec = { type: "purchase", amount: 45, currency: "USD" };
    const nonce = newNonce();
    const approval = await createApproval(approvalRequestFor(w.card, ORDERS, action, nonce), w.person, new Date(w.now().getTime() - 11 * 60_000));
    expect(reason(await send(w, { action, nonce, approval }))).toBe("approval_invalid");
  });

  it("11a. malformed card: unknown field", async () => {
    const w = await makeWorld();
    const r = await send(w, {
      mutate: (h) => {
        const card = JSON.parse(Buffer.from(h["kinlet-card"] as string, "base64url").toString());
        card.extra = true;
        h["kinlet-card"] = Buffer.from(JSON.stringify(card)).toString("base64url");
      },
    });
    expect(reason(r)).toBe("card_malformed");
  });

  it("11b. malformed card: wrong version context", async () => {
    const w = await makeWorld();
    const r = await send(w, {
      mutate: (h) => {
        const card = JSON.parse(Buffer.from(h["kinlet-card"] as string, "base64url").toString());
        card["@context"][1] = "https://kinlet.dev/ns/card/v2";
        h["kinlet-card"] = Buffer.from(JSON.stringify(card)).toString("base64url");
      },
    });
    expect(reason(r)).toBe("card_malformed");
  });

  it("11c. missing signature headers", async () => {
    const w = await makeWorld();
    const r = await send(w, { mutate: (h) => delete h["signature"] });
    expect(reason(r)).toBe("request_signature_invalid");
  });
});

describe("issuance rules", () => {
  it("refuses monetary actions without limits", async () => {
    const person = await generateKeyPair();
    const agent = await generateKeyPair();
    await expect(
      issueCard({ issuer: person, agentDid: agent.did, name: "x", directory: DIRECTORY, permissions: { services: [SHOP], actions: ["purchase"] } }),
    ).rejects.toThrow(/limits/);
  });

  it("refuses wildcard or non-https services", async () => {
    const person = await generateKeyPair();
    const agent = await generateKeyPair();
    for (const bad of ["*", "http://shop.example.com", "https://shop.example.com/path", "shop.example.com"]) {
      await expect(issueCard({ issuer: person, agentDid: agent.did, name: "x", directory: DIRECTORY, permissions: { services: [bad], actions: ["read"] } })).rejects.toThrow();
    }
  });

  it("refuses lifetimes over 90 days", async () => {
    const person = await generateKeyPair();
    const agent = await generateKeyPair();
    const from = new Date("2026-01-01T00:00:00Z");
    await expect(
      issueCard({ issuer: person, agentDid: agent.did, name: "x", directory: DIRECTORY, permissions: { services: [SHOP], actions: ["read"] }, validFrom: from, validUntil: new Date("2026-05-01T00:00:00Z") }),
    ).rejects.toThrow(/90 days/);
  });

  it("refuses issuer == agent", async () => {
    const person = await generateKeyPair();
    await expect(issueCard({ issuer: person, agentDid: person.did, name: "x", directory: DIRECTORY, permissions: { services: [SHOP], actions: ["read"] } })).rejects.toThrow(/different keys/);
  });
});
