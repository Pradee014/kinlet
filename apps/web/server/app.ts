/**
 * Card office server as a composable Hono app: passkey (WebAuthn) registration and login, sessions,
 * and static files. It never sees a Kinlet key. The person's root key lives in their browser; this
 * server only knows passkey public keys and who is logged in.
 */
import { serveStatic } from "@hono/node-server/serve-static";
import { Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { existsSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { createAuthRoutes } from "./auth.js";
import { WebStore } from "./store.js";

export interface WebAppOptions {
  store: WebStore;
  /** Public origin the browser sees, e.g. https://kinlet.fly.dev. WebAuthn checks it. */
  origin: string;
  rpId?: string;
  /** Where the client should find the directory and the demo shop. */
  directoryUrl: string;
  merchantUrl: string;
  /** Directory of built client files; defaults to the package's dist/client. */
  clientDir?: string;
}

export function createWebApp(opts: WebAppOptions): Hono {
  const { store, origin, directoryUrl, merchantUrl } = opts;
  const rpId = opts.rpId ?? new URL(origin).hostname;
  const secure = origin.startsWith("https://");
  const app = new Hono();

  app.use("*", async (c, next) => {
    await next();
    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Frame-Options", "DENY");
    c.header("Referrer-Policy", "no-referrer");
    c.header(
      "Content-Security-Policy",
      `default-src 'self'; connect-src 'self' ${new URL(directoryUrl).origin} ${new URL(merchantUrl).origin}; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
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
  const clientDir = opts.clientDir ?? join(here, "..", "client");
  if (existsSync(clientDir)) {
    // serveStatic roots are relative to the process cwd.
    const root = relative(process.cwd(), clientDir) || ".";
    app.use("/*", serveStatic({ root, rewriteRequestPath: (p) => (p === "/" ? "/index.html" : p) }));
    app.get("*", serveStatic({ path: join(root, "index.html") }));
  }
  return app;
}

/** Resolves the signed-in user id from a raw Request's session cookie. Used by sibling apps (remote MCP). */
export function sessionUserId(store: WebStore, req: Request): string | undefined {
  const cookie = req.headers.get("cookie") ?? "";
  const m = /(?:^|;\s*)kinlet_session=([^;]+)/.exec(cookie);
  if (!m) return undefined;
  const s = store.getSession(decodeURIComponent(m[1] as string));
  return s?.userId;
}
