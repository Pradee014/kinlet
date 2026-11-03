#!/usr/bin/env node
/**
 * Starts the directory (7001), the demo merchant (7002) and the card office (7000) together.
 *   pnpm demo
 * Data lives in ./data/demo. Ctrl-C stops all three.
 */
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const data = join(root, "data", "demo");
mkdirSync(data, { recursive: true });

const procs = [
  ["directory", "packages/directory/dist/cli.js", { KINLET_DIRECTORY_DATA: join(data, "directory") }],
  ["merchant", "packages/demo-merchant/dist/cli.js", {}],
  ["web", "apps/web/dist/server/index.js", { KINLET_WEB_DATA: join(data, "web") }],
].map(([name, script, env]) => {
  const p = spawn(process.execPath, [join(root, script)], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  const tag = (line) => `[${name}] ${line}`;
  p.stdout.on("data", (d) => process.stdout.write(String(d).split("\n").filter(Boolean).map(tag).join("\n") + "\n"));
  p.stderr.on("data", (d) => process.stderr.write(String(d).split("\n").filter(Boolean).map(tag).join("\n") + "\n"));
  return p;
});

const stop = () => {
  for (const p of procs) p.kill("SIGTERM");
  process.exit(0);
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
setTimeout(() => console.log("\nOpen http://localhost:7000 in your browser.\n"), 1500);
