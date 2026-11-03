/**
 * The full one-tap flow, in-process: client registers, authorize parks the request, the app
 * approves with a credential, token exchange with PKCE, then MCP calls through the hosted runtime
 * reach the demo shop and the directory.
 */
import { describe, expect, it } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import { base64urlEncode, exportPrivateKeyOnce, fetchDirectoryClient, generateKeyPair, issueCard, signRevocation } from "@kinlet/core";
import { createDirectoryApp, Store } from "@kinlet/directory";
import { createMerchantApp } from "@kinlet/demo-merchant";
import { Hono } from "hono";
import { createRemoteApp, RemoteStore } from "../src/index.js";

const ORIGIN = "https://kinlet.test";
const DIR = ORIGIN + "/d";

async function world() {
  const dirKey = await generateKeyPair();
  const directory = createDirectoryApp({ key: dirKey, store: new Store(":memory:"), publicUrl: DIR });
  // Mounted exactly as the deployable server mounts them, so signed URLs match.
  const root = new Hono();
  const fetchFn: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (!url.startsWith(ORIGIN)) throw new Error("unexpected " + url);
    return root.request(url, init);
  };
  const shop = createMerchantApp({ origin: ORIGIN, directory: fetchDirectoryClient(fetchFn) });
  let signedInUser: string | undefined = "user_1";
  const remote = createRemoteApp({ store: new RemoteStore(":memory:", new Uint8Array(randomBytes(32))), publicUrl: ORIGIN, currentUserId: async () => signedInUser, fetchFn });
  root.route("/d", directory);
  root.route("/shop", shop.app);
  root.route("/", remote);

  const person = await generateKeyPair();
  const agent = await generateKeyPair({ extractable: true });
  const card = await issueCard({ issuer: person, agentDid: agent.did, name: "Hosted shopper", directory: DIR, permissions: { services: [ORIGIN], actions: ["read", "purchase"], limits: { currency: "USD", perAction: 50, perDay: 100 }, approval: { above: 40 } } });
  await fetchFn(DIR + "/v1/cards", { method: "POST", body: JSON.stringify(card), headers: { "content-type": "application/json" } });
  const credential = base64urlEncode(new TextEncoder().encode(JSON.stringify({ version: 1, card, agent: { publicKey: base64urlEncode(agent.publicKey), privateKeyPkcs8: base64urlEncode(await exportPrivateKeyOnce(agent)) } })));
  return { remote, fetchFn, person, card, credential, setUser: (u: string | undefined) => (signedInUser = u) };
}

const json = (body: unknown) => ({ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
const form = (fields: Record<string, string>) => ({ method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields).toString() });

async function connect(w: Awaited<ReturnType<typeof world>>) {
  const reg = await w.remote.request("/oauth/register", json({ redirect_uris: ["https://claude.ai/api/mcp/auth_callback"], client_name: "Claude" }));
  expect(reg.status).toBe(201);
  const { client_id } = (await reg.json()) as { client_id: string };
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const authz = await w.remote.request(`/oauth/authorize?response_type=code&client_id=${client_id}&redirect_uri=${encodeURIComponent("https://claude.ai/api/mcp/auth_callback")}&code_challenge=${challenge}&code_challenge_method=S256&state=xyz&scope=agent`);
  expect(authz.status).toBe(302);
  const reqId = (authz.headers.get("location") ?? "").split("/connect-claude/")[1] as string;
  expect(reqId).toMatch(/^req_/);
  const pending = await w.remote.request(`/oauth/pending/${reqId}`);
  expect(((await pending.json()) as { clientName: string }).clientName).toBe("Claude");
  const approve = await w.remote.request("/oauth/approve", json({ id: reqId, decision: "approved", credential: w.credential }));
  expect(approve.status).toBe(200);
  const redirect = new URL(((await approve.json()) as { redirect: string }).redirect);
  expect(redirect.searchParams.get("state")).toBe("xyz");
  const code = redirect.searchParams.get("code") as string;
  return { client_id, verifier, code };
}

describe("hosted MCP with OAuth", () => {
  it("registers, authorizes, exchanges with PKCE, and serves tools", async () => {
    const w = await world();
    const { client_id, verifier, code } = await connect(w);

    // Wrong verifier is rejected; the code is single-use, so get a fresh one for the real exchange.
    const bad = await w.remote.request("/oauth/token", form({ grant_type: "authorization_code", client_id, code, code_verifier: "wrong" }));
    expect(bad.status).toBe(400);
    const second = await connect(w);
    const tok = await w.remote.request("/oauth/token", form({ grant_type: "authorization_code", client_id: second.client_id, code: second.code, code_verifier: second.verifier }));
    expect(tok.status).toBe(200);
    const { access_token, refresh_token } = (await tok.json()) as { access_token: string; refresh_token: string };

    // Unauthenticated MCP call points at the resource metadata.
    const anon = await w.remote.request("/mcp", json({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }));
    expect(anon.status).toBe(401);
    expect(anon.headers.get("www-authenticate")).toContain("oauth-protected-resource");

    const mcp = async (body: unknown) =>
      w.remote.request("/mcp", { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${access_token}` }, body: JSON.stringify(body) });
    const parse = async (res: Response) => {
      const text = await res.text();
      const line = text.split("\n").find((l) => l.startsWith("data:"));
      return JSON.parse(line ? line.slice(5) : text) as { result?: Record<string, unknown>; error?: unknown };
    };

    const init = await parse(await mcp({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } } }));
    expect((init.result as { serverInfo: { name: string } }).serverInfo.name).toBe("kinlet-agent");

    const tools = await parse(await mcp({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }));
    expect((tools.result as { tools: { name: string }[] }).tools.map((t) => t.name).sort()).toEqual(["kinlet_act", "kinlet_card", "kinlet_check"]);

    const buy = await parse(await mcp({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "kinlet_act", arguments: { url: ORIGIN + "/shop/orders", method: "POST", body: JSON.stringify({ sku: "lamp-01" }), action: { type: "purchase", amount: 12.5, currency: "USD", ref: "lamp-01" } } } }));
    const text = (buy.result as { content: { text: string }[] }).content[0]!.text;
    expect(JSON.parse(text).status).toBe(201);

    // Refresh rotates; the old refresh token dies.
    const r1 = await w.remote.request("/oauth/token", form({ grant_type: "refresh_token", client_id: second.client_id, refresh_token }));
    expect(r1.status).toBe(200);
    const r2 = await w.remote.request("/oauth/token", form({ grant_type: "refresh_token", client_id: second.client_id, refresh_token }));
    expect(r2.status).toBe(400);

    // Cancelling the card makes the hosted agent useless even though the token is still valid.
    const rev = await signRevocation({ serial: w.card.credentialStatus.serial }, w.person);
    await w.fetchFn(DIR + `/v1/cards/${w.card.credentialStatus.serial}/revoke`, json(rev));
    const after = await parse(await mcp({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "kinlet_act", arguments: { url: ORIGIN + "/shop/orders", method: "POST", body: JSON.stringify({ sku: "mug-02" }), action: { type: "purchase", amount: 8, currency: "USD", ref: "mug-02" } } } }));
    expect(JSON.parse((after.result as { content: { text: string }[] }).content[0]!.text).reason).toBe("card_revoked");

    // Disconnecting kills the token outright.
    const list = (await (await w.remote.request("/connections")).json()) as { connections: { id: string }[] };
    await w.remote.request(`/connections/${list.connections[0]!.id}/revoke`, json({}));
    expect((await mcp({ jsonrpc: "2.0", id: 5, method: "tools/list", params: {} })).status).toBe(401);
  });

  it("refuses consent without a signed-in person and refuses unknown redirect URIs", async () => {
    const w = await world();
    const reg = await w.remote.request("/oauth/register", json({ redirect_uris: ["https://claude.ai/cb"] }));
    const { client_id } = (await reg.json()) as { client_id: string };
    const evil = await w.remote.request(`/oauth/authorize?response_type=code&client_id=${client_id}&redirect_uri=${encodeURIComponent("https://evil.test/cb")}&code_challenge=abc&code_challenge_method=S256`);
    expect(evil.status).toBe(400);
    w.setUser(undefined);
    const approve = await w.remote.request("/oauth/approve", json({ id: "req_x", decision: "approved", credential: w.credential }));
    expect(approve.status).toBe(401);
    expect((await w.remote.request("/oauth/register", json({ redirect_uris: ["javascript:alert(1)"] }))).status).toBe(400);
  });
});
