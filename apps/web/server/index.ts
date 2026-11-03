/**
 * Card office server: passkey (WebAuthn) registration and login, sessions, and static files.
 * It never sees a Kinlet key. The person's root key lives in their browser; this server only
 * knows passkey public keys and who is logged in.
 *
 *   KINLET_WEB_PORT        default 7000
 *   KINLET_WEB_ORIGIN      default http://localhost:<port>   (WebAuthn origin; must match the browser)
 *   KINLET_WEB_RP_ID       default localhost
 *   KINLET_WEB_DATA        default ./data
 *   KINLET_DIRECTORY_URL   default http://localhost:7001     (handed to the client)
 *   KINLET_MERCHANT_URL    default http://localhost:7002     (demo only; pre-fills the service field)
 */
import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createAuthRoutes } from "./auth.js";
import { WebStore } from "./store.js";

const port = Number(process.env["KINLET_WEB_PORT"] ?? "7000");
const origin = process.env["KINLET_WEB_ORIGIN"] ?? `http://localhost:${port}`;
const rpId = process.env["KINLET_WEB_RP_ID"] ?? new URL(origin).hostname;
const dataDir = process.env["KINLET_WEB_DATA"] ?? join(process.cwd(), "data");
const directoryUrl = process.env["KINLET_DIRECTORY_URL"] ?? "http://localhost:7001";
const merchantUrl = process.env["KINLET_MERCHANT_URL"] ?? "http://localhost:7002";

mkdirSync(dataDir, { recursive: true });
const store = new WebStore(join(dataDir, "web.db"));
const app = new Hono();
const secure = origin.startsWith("https://");

app.use("*", async (c, next) => {
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  c.header("Referrer-Policy", "no-referrer");
  c.header(
    "Content-Security-Policy",
    `default-src 'self'; connect-src 'self' ${directoryUrl} ${merchantUrl}; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
  );
  if (secure) c.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
});

app.get("/config", (c) => c.json({ directoryUrl, merchantUrl, rpId, origin }));

app.route(
  "/auth",
  createAuthRoutes({
    store,
    rpId,
    rpName: "Kinlet",
    origin,
    getSession: (c) => getCookie(c, "kinlet_session"),
    setSession: (c, id) => setCookie(c, "kinlet_session", id, { httpOnly: true, sameSite: "Strict", secure, path: "/", maxAge: 60 * 60 * 12 }),
    clearSession: (c) => deleteCookie(c, "kinlet_session", { path: "/" }),
  }),
);

const here = dirname(fileURLToPath(import.meta.url));
const clientDir = join(here, "..", "client");
if (existsSync(clientDir)) {
  app.use("/*", serveStatic({ root: clientDir, rewriteRequestPath: (p) => (p === "/" ? "/index.html" : p) }));
  app.get("*", serveStatic({ path: join(clientDir, "index.html") }));
}

serve({ fetch: app.fetch, port }, () => console.log(`kinlet web listening on ${origin} (directory ${directoryUrl})`));
