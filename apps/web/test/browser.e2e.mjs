/**
 * Browser end-to-end check. Requires the three services running locally:
 *   directory :7001, merchant :7002, web :7000.
 * Uses Chromium's virtual authenticator so the passkey ceremony runs without hardware.
 *   node apps/web/test/browser.e2e.mjs
 */
import { chromium } from "playwright";
import { AgentRuntime, parseCredential } from "@kinlet/mcp";

const WEB = process.env.KINLET_WEB_ORIGIN ?? "http://localhost:7000";
const SHOP = process.env.KINLET_MERCHANT_URL ?? "http://localhost:7002";
const username = "demo" + Math.random().toString(36).slice(2, 8);

const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
});
page.on("pageerror", (e) => console.error("page error:", e.message));

const step = (s) => console.log("•", s);

step("register with a passkey");
await page.goto(WEB);
await page.fill("#u", username);
await page.click("#reg");
await page.waitForSelector("text=Your agents");

step("create a shopping agent");
await page.click("#new");
await page.fill("#name", "Shopper");
await page.selectOption("#tpl", "shopping");
await page.click("#create");
await page.waitForSelector("#code");
const credential = (await page.textContent("#code")).trim();
if (credential.length < 100) throw new Error("credential too short");
await page.click("#done");
await page.waitForSelector("text=Activity");
const serial = new URL(page.url()).hash.split("/").pop();
step(`card ${serial} issued and registered`);

step("agent buys a lamp (no approval needed)");
const runtime = await AgentRuntime.create({ credential: parseCredential(credential), approvalPollMs: 300, approvalTimeoutMs: 30_000 });
const lamp = await runtime.act({ url: SHOP + "/orders", method: "POST", body: JSON.stringify({ sku: "lamp-01" }), action: { type: "purchase", amount: 12.5, currency: "USD", ref: "lamp-01" } });
if (lamp.status !== 201) throw new Error("lamp purchase failed: " + JSON.stringify(lamp));

step("agent tries a chair; owner approves in the app");
const chairPromise = runtime.act({ url: SHOP + "/orders", method: "POST", body: JSON.stringify({ sku: "chair-03" }), action: { type: "purchase", amount: 45, currency: "USD", ref: "chair-03" } });
await page.waitForSelector("#openApprovals", { timeout: 15_000 });
await page.click("#openApprovals");
await page.waitForSelector("text=Buy chair-03 for $45.00");
await page.click("[data-approve]");
const chair = await chairPromise;
if (chair.status !== 201 || chair.approvalOutcome !== "approved") throw new Error("chair purchase failed: " + JSON.stringify(chair));

step("agent tries a desk over the per-action limit: refused locally");
const desk = await runtime.act({ url: SHOP + "/orders", method: "POST", body: JSON.stringify({ sku: "desk-04" }), action: { type: "purchase", amount: 240, currency: "USD", ref: "desk-04" } });
if (desk.reason !== "limit_exceeded") throw new Error("desk should be refused: " + JSON.stringify(desk));

step("owner cancels the card");
await page.goto(`${WEB}/#/agent/${serial}`);
page.once("dialog", (d) => d.accept());
await page.click("#revoke");
await page.waitForSelector("text=cancelled");

step("agent is refused everywhere");
const after = await runtime.act({ url: SHOP + "/orders", method: "POST", body: JSON.stringify({ sku: "mug-02" }), action: { type: "purchase", amount: 8, currency: "USD", ref: "mug-02" } });
if (after.reason !== "card_revoked") throw new Error("should be revoked: " + JSON.stringify(after));

step("activity feed shows every attempt in plain language");
await page.reload();
await page.waitForSelector("text=Buy mug-02 for $8.00");
const feed = await page.$$eval(".feed li", (els) => els.map((e) => e.textContent.replace(/\s+/g, " ").trim()));
console.log(feed.map((f) => "    " + f).join("\n"));
if (!feed.some((f) => f.includes("you cancelled this card"))) throw new Error("feed missing revocation reason");
if (!feed.some((f) => f.includes("over the spending limit"))) throw new Error("feed missing limit reason");

await page.screenshot({ path: "/tmp/kinlet-demo/agent-screen.png", fullPage: true });
await browser.close();
console.log("\nPASS: browser end-to-end");
