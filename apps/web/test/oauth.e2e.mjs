/**
 * One-tap connect, end to end, against the all-in-one server (PORT 8080 by default):
 * an MCP client registers, the person signs in with a passkey and approves in the browser,
 * the client exchanges the code and calls tools through the hosted runtime.
 *   node apps/web/test/oauth.e2e.mjs
 */
import { chromium } from "playwright";
import { createHash, randomBytes } from "node:crypto";

const ORIGIN = process.env.KINLET_PUBLIC_URL ?? "http://localhost:8080";
const CALLBACK = "http://localhost:9999/callback";
const step = (s) => console.log("•", s);

step("MCP client discovers and registers");
const meta = await (await fetch(ORIGIN + "/.well-known/oauth-authorization-server")).json();
const reg = await (await fetch(meta.registration_endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [CALLBACK], client_name: "Claude (test)" }) })).json();
const verifier = randomBytes(32).toString("base64url");
const challenge = createHash("sha256").update(verifier).digest("base64url");
const authorizeUrl = `${meta.authorization_endpoint}?response_type=code&client_id=${reg.client_id}&redirect_uri=${encodeURIComponent(CALLBACK)}&code_challenge=${challenge}&code_challenge_method=S256&state=s1&scope=agent`;

step("person opens the authorize link, signs in with a passkey, approves");
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 420, height: 820 }, deviceScaleFactor: 2 });
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
// Nothing listens on the callback port; answer it in-browser so the navigation lands.
await page.route(CALLBACK + "*", (route) => route.fulfill({ status: 200, contentType: "text/html", body: "<title>callback</title>ok" }));
await page.goto(authorizeUrl);
await page.waitForSelector("#u");
await page.fill("#u", "oauth" + Math.random().toString(36).slice(2, 7));
await page.click("#reg");
await page.waitForSelector("text=wants to act for you");
await page.screenshot({ path: "/tmp/kinlet-demo/shots/10-consent.png", fullPage: true });
await page.click("#approve");
await page.waitForURL((u) => u.toString().startsWith(CALLBACK), { timeout: 20_000 });
const cbUrl = new URL(page.url());
if (!cbUrl.toString().startsWith(CALLBACK)) throw new Error("did not reach callback: " + page.url());
const code = cbUrl.searchParams.get("code");
if (!code || cbUrl.searchParams.get("state") !== "s1") throw new Error("bad callback " + page.url());
step("callback reached with a code");

step("client exchanges the code (PKCE) and calls tools");
const tok = await (await fetch(meta.token_endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", client_id: reg.client_id, code, code_verifier: verifier, redirect_uri: CALLBACK }) })).json();
if (!tok.access_token) throw new Error("no token: " + JSON.stringify(tok));
const mcp = async (body) => {
  const res = await fetch(ORIGIN + "/mcp", { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${tok.access_token}` }, body: JSON.stringify(body) });
  const text = await res.text();
  const line = text.split("\n").find((l) => l.startsWith("data:"));
  return JSON.parse(line ? line.slice(5) : text);
};
await mcp({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } } });
const card = await mcp({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "kinlet_card", arguments: {} } });
console.log("    card:", JSON.parse(card.result.content[0].text).name);
const buy = await mcp({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "kinlet_act", arguments: { url: ORIGIN + "/shop/orders", method: "POST", body: JSON.stringify({ sku: "lamp-01" }), action: { type: "purchase", amount: 12.5, currency: "USD", ref: "lamp-01" } } } });
const r = JSON.parse(buy.result.content[0].text);
if (r.status !== 201) throw new Error("buy failed: " + buy.result.content[0].text);
step("hosted agent bought the lamp through the shop");

step("home screen lists the connection; disconnect kills the token");
await page.goto(ORIGIN + "/#/");
await page.waitForSelector("[data-disconnect]");
await page.screenshot({ path: "/tmp/kinlet-demo/shots/11-home-connected.png", fullPage: true });
page.once("dialog", (d) => d.accept());
await page.click("[data-disconnect]");
await page.waitForSelector("text=Nothing connected yet");
const after = await fetch(ORIGIN + "/mcp", { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${tok.access_token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/list", params: {} }) });
if (after.status !== 401) throw new Error("token still works after disconnect");
await browser.close();
console.log("\nPASS: one-tap connect end-to-end");
