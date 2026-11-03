#!/usr/bin/env node
/**
 * Runs the directory. Configuration by environment:
 *   KINLET_DIRECTORY_PORT   default 7001
 *   KINLET_DIRECTORY_URL    public origin, default http://localhost:<port>
 *   KINLET_DIRECTORY_DATA   directory for the SQLite db and key file, default ./data
 */
import { serve } from "@hono/node-server";
import { join } from "node:path";
import { createDirectoryApp } from "./app.js";
import { loadOrCreateKey } from "./keyfile.js";
import { Store } from "./store.js";

const port = Number(process.env["KINLET_DIRECTORY_PORT"] ?? "7001");
const publicUrl = process.env["KINLET_DIRECTORY_URL"] ?? `http://localhost:${port}`;
const dataDir = process.env["KINLET_DIRECTORY_DATA"] ?? join(process.cwd(), "data");

const key = await loadOrCreateKey(join(dataDir, "directory-key.json"));
const store = new Store(join(dataDir, "directory.db"));
const app = createDirectoryApp({ key, store, publicUrl });

serve({ fetch: app.fetch, port }, () => {
  console.log(`kinlet directory listening on ${publicUrl} as ${key.did}`);
});
