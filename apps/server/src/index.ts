/**
 * The deployable Kinlet: card office at /, directory at /d, demo shop at /shop, one origin.
 *   PORT                 default 8080
 *   KINLET_PUBLIC_URL    the public https origin, e.g. https://kinlet.fly.dev (required in production)
 *   KINLET_DATA          directory for SQLite files and the directory key, default ./data
 */
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { createDirectoryApp, loadOrCreateKey, Store } from "@kinlet/directory";
import { createMerchantApp } from "@kinlet/demo-merchant";
import { fetchDirectoryClient } from "@kinlet/core";
import { createWebApp } from "@kinlet/web";
import { WebStore } from "@kinlet/web/store";

const port = Number(process.env["PORT"] ?? "8080");
const publicUrl = (process.env["KINLET_PUBLIC_URL"] ?? `http://localhost:${port}`).replace(/\/$/, "");
const dataDir = process.env["KINLET_DATA"] ?? join(process.cwd(), "data");
mkdirSync(dataDir, { recursive: true });

const directoryUrl = publicUrl + "/d";
const merchantOrigin = publicUrl; // the shop lives under /shop on the same origin

const key = await loadOrCreateKey(join(dataDir, "directory-key.json"));
const directory = createDirectoryApp({ key, store: new Store(join(dataDir, "directory.db")), publicUrl: directoryUrl });

// The shop verifies cards by calling the directory in-process: no network hop, same fail-closed rules.
const localFetch: typeof fetch = async (input, init) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  if (url.startsWith(directoryUrl)) return directory.request(url.slice(directoryUrl.length) || "/", init);
  return fetch(input, init);
};
const { app: shop } = createMerchantApp({ origin: merchantOrigin, directory: fetchDirectoryClient(localFetch) });

const require = createRequire(import.meta.url);
const webPkgDir = dirname(require.resolve("@kinlet/web/package.json"));
const web = createWebApp({
  store: new WebStore(join(dataDir, "web.db")),
  origin: publicUrl,
  directoryUrl,
  merchantUrl: merchantOrigin + "/shop",
  clientDir: join(webPkgDir, "dist", "client"),
});

const app = new Hono();
app.route("/d", directory);
app.route("/shop", shop);
app.route("/", web);

serve({ fetch: app.fetch, port, hostname: "0.0.0.0" }, () => {
  console.log(`kinlet listening on ${publicUrl} (port ${port}); directory ${directoryUrl}; shop ${merchantOrigin}/shop; directory key ${key.did}`);
});
