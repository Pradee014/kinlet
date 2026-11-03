import { describe, expect, it } from "vitest";
import {
  checkStatusDoc,
  createOwnerProof,
  eventHash,
  GENESIS_HASH,
  generateKeyPair,
  issueCard,
  signEvent,
  signRevocation,
} from "@kinlet/core";
import { createDirectoryApp } from "../src/app.js";
import { Store } from "../src/store.js";

const URL_ = "https://directory.test";

async function setup() {
  const key = await generateKeyPair();
  const store = new Store(":memory:");
  let current = new Date("2026-11-03T12:00:00Z");
  const app = createDirectoryApp({ key, store, publicUrl: URL_, now: () => current });
  const person = await generateKeyPair();
  const agent = await generateKeyPair();
  const card = await issueCard({ issuer: person, agentDid: agent.did, name: "a", directory: URL_, validFrom: current, permissions: { services: ["https://shop.test"], actions: ["read"] } });
  const call = (path: string, init?: RequestInit) => app.request(URL_ + path, init);
  const json = (body: unknown, headers: Record<string, string> = {}) => ({ method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json", ...headers } });
  return { key, store, app, person, agent, card, call, json, setNow: (d: Date) => (current = d), now: () => current };
}

describe("directory", () => {
  it("publishes its did", async () => {
    const s = await setup();
    const res = await s.call("/.well-known/kinlet.json");
    expect(res.status).toBe(200);
    expect(((await res.json()) as { did: string }).did).toBe(s.key.did);
  });

  it("registers a card and answers signed status", async () => {
    const s = await setup();
    const serial = s.card.credentialStatus.serial;
    const before = await (await s.call(`/v1/cards/${serial}/status`)).json();
    expect((await checkStatusDoc(before, { serial, directoryDid: s.key.did }, s.now())).ok).toBe(true);
    expect((before as { status: string }).status).toBe("unknown");

    const reg = await s.call("/v1/cards", s.json(s.card));
    expect(reg.status).toBe(201);

    const after = (await (await s.call(`/v1/cards/${serial}/status`)).json()) as { status: string };
    expect(after.status).toBe("valid");
    const check = await checkStatusDoc(after, { serial, directoryDid: s.key.did }, s.now());
    expect(check.ok).toBe(true);
  });

  it("rejects a tampered card and a card naming another directory", async () => {
    const s = await setup();
    const tampered = { ...s.card, validUntil: "2027-01-01T00:00:00Z" };
    expect((await s.call("/v1/cards", s.json(tampered))).status).toBe(400);
    const other = await issueCard({ issuer: s.person, agentDid: s.agent.did, name: "a", directory: "https://elsewhere.test", permissions: { services: ["https://shop.test"], actions: ["read"] } });
    expect((await s.call("/v1/cards", s.json(other))).status).toBe(400);
  });

  it("revokes only with the issuer's signature, permanently", async () => {
    const s = await setup();
    const serial = s.card.credentialStatus.serial;
    await s.call("/v1/cards", s.json(s.card));
    const forged = await signRevocation({ serial }, s.agent, s.now());
    expect((await s.call(`/v1/cards/${serial}/revoke`, s.json(forged))).status).toBe(400);
    const real = await signRevocation({ serial, reason: "lost phone" }, s.person, s.now());
    const res = await s.call(`/v1/cards/${serial}/revoke`, s.json(real));
    expect(res.status).toBe(200);
    expect(((await res.json()) as { status: string }).status).toBe("revoked");
    // Re-registering the same card does not un-revoke it.
    await s.call("/v1/cards", s.json(s.card));
    expect(((await (await s.call(`/v1/cards/${serial}/status`)).json()) as { status: string }).status).toBe("revoked");
  });

  it("accepts chained events and rejects gaps, forks and other keys", async () => {
    const s = await setup();
    const serial = s.card.credentialStatus.serial;
    await s.call("/v1/cards", s.json(s.card));
    const e0 = await signEvent({ serial, seq: 0, prev: GENESIS_HASH, target: "https://shop.test/x", action: { type: "read" }, outcome: "ok" }, s.agent, s.now());
    expect((await s.call(`/v1/cards/${serial}/events`, s.json(e0))).status).toBe(201);
    const h0 = await eventHash(e0);
    const gap = await signEvent({ serial, seq: 2, prev: h0, target: "https://shop.test/x", action: { type: "read" }, outcome: "ok" }, s.agent, s.now());
    expect((await s.call(`/v1/cards/${serial}/events`, s.json(gap))).status).toBe(400);
    const fork = await signEvent({ serial, seq: 1, prev: GENESIS_HASH, target: "https://shop.test/x", action: { type: "read" }, outcome: "ok" }, s.agent, s.now());
    expect((await s.call(`/v1/cards/${serial}/events`, s.json(fork))).status).toBe(400);
    const otherKey = await signEvent({ serial, seq: 1, prev: h0, target: "https://shop.test/x", action: { type: "read" }, outcome: "ok" }, s.person, s.now());
    expect((await s.call(`/v1/cards/${serial}/events`, s.json(otherKey))).status).toBe(400);
    const e1 = await signEvent({ serial, seq: 1, prev: h0, target: "https://shop.test/x", action: { type: "read" }, outcome: "refused:card_revoked" }, s.agent, s.now());
    expect((await s.call(`/v1/cards/${serial}/events`, s.json(e1))).status).toBe(201);
  });

  it("lets only the owner read events and list cards", async () => {
    const s = await setup();
    const serial = s.card.credentialStatus.serial;
    await s.call("/v1/cards", s.json(s.card));
    expect((await s.call(`/v1/cards/${serial}/events`)).status).toBe(401);
    const stranger = await generateKeyPair();
    const strangerProof = await createOwnerProof(stranger, s.now());
    expect((await s.call(`/v1/cards/${serial}/events`, { headers: { "kinlet-owner-proof": strangerProof } })).status).toBe(401);
    const proof = await createOwnerProof(s.person, s.now());
    expect((await s.call(`/v1/cards/${serial}/events`, { headers: { "kinlet-owner-proof": proof } })).status).toBe(200);
    const list = await s.call(`/v1/issuers/${encodeURIComponent(s.person.did)}/cards`, { headers: { "kinlet-owner-proof": proof } });
    expect(list.status).toBe(200);
    expect(((await list.json()) as { cards: unknown[] }).cards).toHaveLength(1);
    // Stale proof is rejected.
    s.setNow(new Date(s.now().getTime() + 5 * 60_000));
    expect((await s.call(`/v1/cards/${serial}/events`, { headers: { "kinlet-owner-proof": proof } })).status).toBe(401);
  });

  it("stores nothing but serial, dids and validity", async () => {
    const s = await setup();
    await s.call("/v1/cards", s.json(s.card));
    const row = s.store.getCard(s.card.credentialStatus.serial)!;
    expect(Object.keys(row).sort()).toEqual(["issuer", "registeredAt", "revocationJson", "revokedAt", "serial", "subject", "validFrom", "validUntil"]);
  });
});

describe("approval relay", () => {
  it("relays a request and an answer without being able to forge either", async () => {
    const s = await setup();
    const serial = s.card.credentialStatus.serial;
    await s.call("/v1/cards", s.json(s.card));
    const { signDocument, createApproval, approvalRequestFor, newNonce } = await import("@kinlet/core");
    const nonce = newNonce();
    const reqDoc = { type: "KinletApprovalRequest" as const, card: serial, target: "https://shop.test/orders", action: { type: "purchase", amount: 45, currency: "USD" }, nonce, at: s.now().toISOString() };
    // Signed by the wrong key: rejected.
    const forged = await signDocument(reqDoc, s.person, { created: s.now() });
    expect((await s.call(`/v1/cards/${serial}/approvals`, s.json(forged))).status).toBe(400);
    const signed = await signDocument(reqDoc, s.agent, { created: s.now() });
    const created = await s.call(`/v1/cards/${serial}/approvals`, s.json(signed));
    expect(created.status).toBe(201);
    const { id } = (await created.json()) as { id: string };

    // Pending for the owner only.
    const proof = await createOwnerProof(s.person, s.now());
    const list = (await (await s.call(`/v1/issuers/${encodeURIComponent(s.person.did)}/approvals`, { headers: { "kinlet-owner-proof": proof } })).json()) as { pending: { id: string }[] };
    expect(list.pending.map((p) => p.id)).toEqual([id]);

    // Still pending from the runtime's view.
    expect(((await (await s.call(`/v1/approvals/${id}`)).json()) as { status: string }).status).toBe("pending");

    // A stranger cannot answer.
    const stranger = await generateKeyPair();
    expect((await s.call(`/v1/approvals/${id}/answer`, s.json({ decision: "denied" }, { "kinlet-owner-proof": await createOwnerProof(stranger, s.now()) }))).status).toBe(401);

    // The owner answers with a real token.
    const token = await createApproval(approvalRequestFor(s.card, "https://shop.test/orders", reqDoc.action, nonce), s.person, s.now());
    expect((await s.call(`/v1/approvals/${id}/answer`, s.json({ decision: "approved", token }, { "kinlet-owner-proof": proof }))).status).toBe(200);
    const got = (await (await s.call(`/v1/approvals/${id}`)).json()) as { status: string; token: string };
    expect(got.status).toBe("approved");
    expect(got.token).toBe(token);
    // Answering twice is a conflict.
    expect((await s.call(`/v1/approvals/${id}/answer`, s.json({ decision: "denied" }, { "kinlet-owner-proof": proof }))).status).toBe(409);
  });
});
