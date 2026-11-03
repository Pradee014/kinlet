#!/usr/bin/env node
/**
 * Starts the Kinlet MCP server over stdio.
 *   KINLET_AGENT_FILE   path to the agent credential file from the Kinlet app, or
 *   KINLET_AGENT        the credential itself (base64url), as pasted from the app
 * The credential is read once at start-up and never printed.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { AgentRuntime, parseCredential, type RuntimeState } from "./runtime.js";
import { createMcpServer } from "./server.js";

const file = process.env["KINLET_AGENT_FILE"];
const inline = process.env["KINLET_AGENT"];
if (!file && !inline) {
  console.error("Set KINLET_AGENT_FILE (path) or KINLET_AGENT (credential) from the Kinlet app's connect step.");
  process.exit(2);
}
const raw = file ? readFileSync(file, "utf8") : (inline as string);
const credential = parseCredential(raw);

const statePath = (file ?? ".kinlet-agent") + ".state.json";
const state = {
  async load(): Promise<RuntimeState | null> {
    return existsSync(statePath) ? (JSON.parse(readFileSync(statePath, "utf8")) as RuntimeState) : null;
  },
  async save(s: RuntimeState): Promise<void> {
    mkdirSync(dirname(statePath), { recursive: true });
    writeFileSync(statePath, JSON.stringify(s), { mode: 0o600 });
  },
};

const runtime = await AgentRuntime.create({ credential, state });
const server = createMcpServer(runtime);
await server.connect(new StdioServerTransport());
console.error(`kinlet agent "${credential.card.credentialSubject.name}" ready (card ${credential.card.credentialStatus.serial})`);
