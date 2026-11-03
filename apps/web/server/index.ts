/**
 * Runs the card office on its own.
 *   KINLET_WEB_PORT        default 7000
 *   KINLET_WEB_ORIGIN      default http://localhost:<port>   (WebAuthn origin; must match the browser)
 *   KINLET_WEB_DATA        default ./data
 *   KINLET_DIRECTORY_URL   default http://localhost:7001
 *   KINLET_MERCHANT_URL    default http://localhost:7002
 */
import { serve } from "@hono/node-server";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { createWebApp } from "./app.js";
import { WebStore } from "./store.js";

const port = Number(process.env["KINLET_WEB_PORT"] ?? "7000");
const origin = process.env["KINLET_WEB_ORIGIN"] ?? `http://localhost:${port}`;
const dataDir = process.env["KINLET_WEB_DATA"] ?? join(process.cwd(), "data");
const directoryUrl = process.env["KINLET_DIRECTORY_URL"] ?? "http://localhost:7001";
const merchantUrl = process.env["KINLET_MERCHANT_URL"] ?? "http://localhost:7002";

mkdirSync(dataDir, { recursive: true });
const app = createWebApp({ store: new WebStore(join(dataDir, "web.db")), origin, directoryUrl, merchantUrl });
serve({ fetch: app.fetch, port }, () => console.log(`kinlet web listening on ${origin} (directory ${directoryUrl})`));
