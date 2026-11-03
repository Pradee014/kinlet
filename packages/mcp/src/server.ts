/**
 * MCP server exposing the runtime as tools. Three tools, no key material in any result.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PRODUCT_NAME } from "@kinlet/core";
import type { ActionSpec } from "@kinlet/core";
import type { AgentRuntime } from "./runtime.js";

/** Drops undefined optional fields so the action is exactly what gets signed. */
function toAction(a: Record<string, unknown>): ActionSpec {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(a)) if (v !== undefined) out[k] = v;
  return out as ActionSpec;
}

export function createMcpServer(runtime: AgentRuntime): McpServer {
  const server = new McpServer({ name: `${PRODUCT_NAME.toLowerCase()}-agent`, version: "0.1.0" });

  server.registerTool(
    "kinlet_card",
    {
      title: "Show my Kinlet card",
      description:
        "Shows the agent's Kinlet card: who it belongs to, which services and actions it may use, spending limits, and when approval from the owner is required. Call this before acting so you stay inside the card.",
      inputSchema: {},
    },
    async () => ({ content: [{ type: "text", text: JSON.stringify(runtime.summary(), null, 2) }] }),
  );

  server.registerTool(
    "kinlet_check",
    {
      title: "Check whether an action is allowed",
      description: "Checks locally whether the card allows an action at a service, and whether the owner's approval would be required. Makes no network request and changes nothing.",
      inputSchema: {
        url: z.string().url().describe("Full URL the request would go to"),
        action: z
          .object({ type: z.string(), amount: z.number().optional(), currency: z.string().optional(), ref: z.string().optional() })
          .passthrough()
          .describe('What the request does, e.g. {"type":"purchase","amount":12.5,"currency":"USD","ref":"lamp-01"}'),
      },
    },
    async ({ url, action }) => ({ content: [{ type: "text", text: JSON.stringify(runtime.precheck({ url, action: toAction(action) }), null, 2) }] }),
  );

  server.registerTool(
    "kinlet_act",
    {
      title: "Act with my Kinlet card",
      description:
        "Sends a request to a service, signed with the agent's card. If the card requires the owner's approval for this action, the owner is asked on their phone and this call waits for the answer (up to two minutes). Returns the service's HTTP status and body. Never retry a refused action with a different amount: that is the owner's decision, not yours.",
      inputSchema: {
        url: z.string().url(),
        method: z.enum(["GET", "POST", "PUT", "DELETE"]).optional(),
        action: z.object({ type: z.string(), amount: z.number().optional(), currency: z.string().optional(), ref: z.string().optional() }).passthrough(),
        body: z.string().optional().describe("JSON body, if any"),
        waitForApproval: z.boolean().optional().describe("Default true. If false, an action needing approval returns 402 immediately."),
      },
    },
    async (input) => {
      const actInput: Parameters<AgentRuntime["act"]>[0] = { url: input.url, action: toAction(input.action) };
      if (input.method) actInput.method = input.method;
      if (input.body !== undefined) actInput.body = input.body;
      if (input.waitForApproval !== undefined) actInput.waitForApproval = input.waitForApproval;
      const result = await runtime.act(actInput);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], isError: !result.ok };
    },
  );

  return server;
}
