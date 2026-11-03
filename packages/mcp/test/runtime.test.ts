/**
 * Integration: real directory app + real merchant app, wired through an in-memory fetch.
 * Issue card -> agent buys -> approval round-trip -> revoke -> refused.
 */
import { describe, expect, it } from "vitest";
import {
  base64urlEncode,
  createApproval,
  createOwnerProof,
  exportPrivateKeyOnce,
  fetchDirectoryClient,
  generateKeyPair,
  issueCard,
  signRevocation,
  type ActionSpec,
} from "@kinlet/core";
import { createDirectoryApp, Store } from "@kinlet/directory";
import { createMerchantApp } from "@kinlet/demo-merchant";
import { AgentRuntime, parseCredential } from "../src/index.js";

const DIR = "https://directory.test";
const SHOP = "https://shop.test";

async function world() {
  const dirKey = await generateKeyPair();
  const store = new Store(":memory:");
  const directoryApp = createDirectoryApp({ key: dirKey, store, publicUrl: DIR });
  const fetchFn: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.startsWith(DIR)) return directoryApp.request(url, init);
    if (url.startsWith(SHOP)) return merchant.app.request(url, init);
    throw new Error("unexpected host " + url);
  };
  const merchant = createMerchantApp({ origin: SHOP, directory: fetchDirectoryClient(fetchFn) });

  const person = await generateKeyPair();
  const agent = await generateKeyPair({ extractable: true });
  const card = await issueCard({
    issuer: person,
    agentDid: agent.did,
    name: "Shopper",
    directory: DIR,
    permissions: { services: [SHOP], actions: ["read", "purchase"], limits: { currency: "USD", perAction: 50, perDay: 100 }, approval: { above: 40 } },
  });
  expect((await fetchFn(`${DIR}/v1/cards`, { method: "POST", body: JSON.stringify(card), headers: { "content-type": "application/json" } })).status).toBe(201);

  const credentialJson = JSON.stringify({ version: 1, card, agent: { publicKey: base64urlEncode(agent.publicKey), privateKeyPkcs8: base64urlEncode(await exportPrivateKeyOnce(agent)) } });
  const runtime = await AgentRuntime.create({ credential: parseCredential(credentialJson), fetchFn, approvalPollMs: 10, approvalTimeoutMs: 2000 });
  return { person, agent, card, runtime, fetchFn, store, merchant };
}

/** Simulates the person's app: polls pending approvals and answers them. */
async function personAnswers(w: Awaited<ReturnType<typeof world>>, decision: "approved" | "denied") {
  for (let i = 0; i < 100; i++) {
    await new Promise((r) => setTimeout(r, 10));
    const proof = await createOwnerProof(w.person);
    const res = await w.fetchFn(`${DIR}/v1/issuers/${encodeURIComponent(w.person.did)}/approvals`, { headers: { "kinlet-owner-proof": proof } });
    const { pending } = (await res.json()) as { pending: { id: string; request: { target: string; action: ActionSpec; nonce: string; card: string } }[] };
    const p = pending[0];
    if (!p) continue;
    const body: { decision: string; token?: string } = { decision };
    if (decision === "approved") body.token = await createApproval({ card: p.request.card, target: p.request.target, action: p.request.action, nonce: p.request.nonce }, w.person);
    await w.fetchFn(`${DIR}/v1/approvals/${p.id}/answer`, { method: "POST", headers: { "content-type": "application/json", "kinlet-owner-proof": proof }, body: JSON.stringify(body) });
    return;
  }
  throw new Error("no approval request appeared");
}

describe("agent runtime end to end", () => {
  it("buys, asks for approval, is refused after revocation, and logs every attempt", async () => {
    const w = await world();
    expect(w.runtime.summary()).not.toHaveProperty("privateKey");

    // 1. A small purchase goes through without asking.
    const buy = await w.runtime.act({ url: SHOP + "/orders", method: "POST", body: JSON.stringify({ sku: "lamp-01" }), action: { type: "purchase", amount: 12.5, currency: "USD", ref: "lamp-01" } });
    expect(buy.status).toBe(201);
    expect(buy.approvalRequested).toBeUndefined();

    // 2. A larger one asks the person; the person approves.
    const answer = personAnswers(w, "approved");
    const chair = await w.runtime.act({ url: SHOP + "/orders", method: "POST", body: JSON.stringify({ sku: "chair-03" }), action: { type: "purchase", amount: 45, currency: "USD", ref: "chair-03" } });
    await answer;
    expect(chair.approvalRequested).toBe(true);
    expect(chair.approvalOutcome).toBe("approved");
    expect(chair.status).toBe(201);

    // 3. Denied approval -> no request is sent to the merchant.
    const ordersBefore = w.merchant.orders.size;
    const deny = personAnswers(w, "denied");
    const denied = await w.runtime.act({ url: SHOP + "/orders", method: "POST", body: JSON.stringify({ sku: "chair-03" }), action: { type: "purchase", amount: 45, currency: "USD", ref: "chair-03" } });
    await deny;
    expect(denied.reason).toBe("approval_denied");
    expect(w.merchant.orders.size).toBe(ordersBefore);

    // 4. Out-of-card actions are refused locally, before any network call.
    const elsewhere = await w.runtime.act({ url: "https://other.test/x", action: { type: "read" } });
    expect(elsewhere.reason).toBe("service_not_allowed");

    // 5. Revoke; the next attempt is refused by the merchant via the directory.
    const rev = await signRevocation({ serial: w.card.credentialStatus.serial, reason: "test" }, w.person);
    expect((await w.fetchFn(`${DIR}/v1/cards/${w.card.credentialStatus.serial}/revoke`, { method: "POST", body: JSON.stringify(rev), headers: { "content-type": "application/json" } })).status).toBe(200);
    const after = await w.runtime.act({ url: SHOP + "/orders", method: "POST", body: JSON.stringify({ sku: "mug-02" }), action: { type: "purchase", amount: 8, currency: "USD", ref: "mug-02" } });
    expect(after.status).toBe(403);
    expect(after.reason).toBe("card_revoked");

    // 6. The activity chain has every attempt, in order, with outcomes.
    const proof = await createOwnerProof(w.person);
    const log = (await (await w.fetchFn(`${DIR}/v1/cards/${w.card.credentialStatus.serial}/events`, { headers: { "kinlet-owner-proof": proof } })).json()) as { events: { seq: number; outcome: string }[] };
    expect(log.events.map((e) => e.outcome)).toEqual(["ok", "ok", "refused:approval_denied", "refused:service_not_allowed", "refused:card_revoked"]);
    expect(log.events.map((e) => e.seq)).toEqual([0, 1, 2, 3, 4]);
  });

  it("rejects a credential whose key does not match its card", async () => {
    const w = await world();
    const other = await generateKeyPair({ extractable: true });
    const bad = JSON.stringify({ version: 1, card: w.card, agent: { publicKey: base64urlEncode(other.publicKey), privateKeyPkcs8: base64urlEncode(await exportPrivateKeyOnce(other)) } });
    await expect(AgentRuntime.create({ credential: parseCredential(bad), fetchFn: w.fetchFn })).rejects.toThrow(/does not match/);
  });
});
