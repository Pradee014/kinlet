import { describe, expect, it } from "vitest";
import { approvalRequestFor, createApproval, generateKeyPair, issueCard, newNonce, signRequest, signStatus, type DirectoryClient } from "@kinlet/core";
import { createMerchantApp } from "../src/app.js";

const SHOP = "https://shop.test";
const DIR = "https://directory.test";

async function setup() {
  const person = await generateKeyPair();
  const agent = await generateKeyPair();
  const dirKey = await generateKeyPair();
  const statuses = new Map<string, "valid" | "revoked">();
  const directory: DirectoryClient = {
    directoryDid: async () => dirKey.did,
    status: async (_u, serial) => signStatus({ serial, status: statuses.get(serial) ?? "unknown" }, dirKey),
  };
  const card = await issueCard({
    issuer: person, agentDid: agent.did, name: "Shopper", directory: DIR,
    permissions: { services: [SHOP], actions: ["read", "purchase", "cancel"], limits: { currency: "USD", perAction: 50, perDay: 60 }, approval: { above: 40, forActions: ["cancel"] } },
  });
  statuses.set(card.credentialStatus.serial, "valid");
  const { app, orders } = createMerchantApp({ origin: SHOP, directory });
  const buy = async (sku: string, amount: number, approval?: string, nonce?: string) => {
    const body = JSON.stringify({ sku });
    const input: Parameters<typeof signRequest>[0] = { agent, card, method: "POST", url: SHOP + "/orders", body, action: { type: "purchase", amount, currency: "USD", ref: sku } };
    if (approval) input.approval = approval;
    if (nonce) input.nonce = nonce;
    const signed = await signRequest(input);
    return app.request(SHOP + "/orders", { method: "POST", body, headers: signed.headers });
  };
  return { person, agent, card, statuses, app, orders, buy };
}

describe("demo merchant", () => {
  it("sells a lamp to a carded agent", async () => {
    const s = await setup();
    const res = await s.buy("lamp-01", 12.5);
    expect(res.status).toBe(201);
    expect(s.orders.size).toBe(1);
  });

  it("refuses without any card headers", async () => {
    const s = await setup();
    const res = await s.app.request(SHOP + "/orders", { method: "POST", body: "{}" });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("request_signature_invalid");
  });

  it("refuses a price the agent did not sign for", async () => {
    const s = await setup();
    expect((await s.buy("lamp-01", 1)).status).toBe(409);
  });

  it("asks for approval above the threshold, then accepts it", async () => {
    const s = await setup();
    const first = await s.buy("chair-03", 45);
    expect(first.status).toBe(402);
    const nonce = newNonce();
    const approval = await createApproval(approvalRequestFor(s.card, SHOP + "/orders", { type: "purchase", amount: 45, currency: "USD", ref: "chair-03" }, nonce), s.person);
    expect((await s.buy("chair-03", 45, approval, nonce)).status).toBe(201);
  });

  it("enforces the daily limit across orders", async () => {
    const s = await setup();
    const chair = { type: "purchase", amount: 45, currency: "USD", ref: "chair-03" };
    const n1 = newNonce();
    expect((await s.buy("chair-03", 45, await createApproval(approvalRequestFor(s.card, SHOP + "/orders", chair, n1), s.person), n1)).status).toBe(201);
    const n2 = newNonce();
    const res = await s.buy("chair-03", 45, await createApproval(approvalRequestFor(s.card, SHOP + "/orders", chair, n2), s.person), n2); // 45 + 45 > 60
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("limit_exceeded");
  });

  it("refuses after revocation", async () => {
    const s = await setup();
    expect((await s.buy("mug-02", 8)).status).toBe(201);
    s.statuses.set(s.card.credentialStatus.serial, "revoked");
    const res = await s.buy("mug-02", 8);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("card_revoked");
  });
});
