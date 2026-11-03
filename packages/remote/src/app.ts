/**
 * OAuth 2.1 authorization server (PKCE, dynamic client registration, public clients) plus the
 * MCP endpoint. The consent step is the card office itself: the person signs in with a passkey,
 * creates (or picks) an agent, and the browser hands the agent credential to this server over the
 * authenticated session. From then on the hosted runtime signs on the agent's behalf.
 *
 * The person's root key never comes here. Cancelling the card in the app makes every token useless,
 * because every request the runtime signs is refused by services from that moment.
 */
import { Hono } from "hono";
import { createHash } from "node:crypto";
import { z } from "zod";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { AgentRuntime, createMcpServer, parseCredential } from "@kinlet/mcp";
import { randomToken, RemoteStore } from "./store.js";

export interface RemoteOptions {
  store: RemoteStore;
  /** Public origin, e.g. https://kinlet.fly.dev. Issuer and resource identifiers derive from it. */
  publicUrl: string;
  /** Resolves the signed-in user id from a request (session cookie), or undefined. */
  currentUserId: (req: Request) => Promise<string | undefined>;
  /** Fetch used by hosted runtimes (tests inject an in-memory one). */
  fetchFn?: typeof fetch;
  now?: () => Date;
}

const PENDING_MAX_AGE_MS = 10 * 60_000;
const CODE_TTL_MS = 5 * 60_000;
const ACCESS_TTL_MS = 30 * 24 * 60 * 60_000;
const REFRESH_TTL_MS = 180 * 24 * 60 * 60_000;

const RegisterSchema = z
  .object({
    redirect_uris: z.array(z.string().url()).min(1).max(10),
    client_name: z.string().max(100).optional(),
    token_endpoint_auth_method: z.string().optional(),
    grant_types: z.array(z.string()).optional(),
    response_types: z.array(z.string()).optional(),
    scope: z.string().optional(),
  })
  .passthrough();

function isAllowedRedirect(uri: string): boolean {
  try {
    const u = new URL(uri);
    if (u.protocol === "https:") return true;
    if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) return true;
    return /^[a-z][a-z0-9+.-]*:$/.test(u.protocol) && u.protocol !== "javascript:" && u.protocol !== "data:"; // custom app schemes
  } catch {
    return false;
  }
}

function s256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export function createRemoteApp(opts: RemoteOptions): Hono {
  const { store } = opts;
  const publicUrl = opts.publicUrl.replace(/\/$/, "");
  const now = opts.now ?? (() => new Date());
  const resource = publicUrl + "/mcp";
  const app = new Hono();
  const runtimes = new Map<string, Promise<AgentRuntime>>();

  app.use("*", async (c, next) => {
    await next();
    c.header("Cache-Control", "no-store");
  });

  // ---- discovery ----
  const metadata = {
    issuer: publicUrl,
    authorization_endpoint: publicUrl + "/oauth/authorize",
    token_endpoint: publicUrl + "/oauth/token",
    registration_endpoint: publicUrl + "/oauth/register",
    revocation_endpoint: publicUrl + "/oauth/revoke",
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["agent"],
  };
  app.get("/.well-known/oauth-authorization-server", (c) => c.json(metadata));
  app.get("/.well-known/oauth-authorization-server/mcp", (c) => c.json(metadata));
  app.get("/.well-known/oauth-protected-resource", (c) => c.json({ resource, authorization_servers: [publicUrl], scopes_supported: ["agent"], bearer_methods_supported: ["header"] }));
  app.get("/.well-known/oauth-protected-resource/mcp", (c) => c.json({ resource, authorization_servers: [publicUrl], scopes_supported: ["agent"], bearer_methods_supported: ["header"] }));

  // ---- dynamic client registration (RFC 7591) ----
  app.post("/oauth/register", async (c) => {
    const parsed = RegisterSchema.safeParse(await c.req.json().catch(() => ({})));
    if (!parsed.success) return c.json({ error: "invalid_client_metadata" }, 400);
    if (!parsed.data.redirect_uris.every(isAllowedRedirect)) return c.json({ error: "invalid_redirect_uri" }, 400);
    const id = "cl_" + randomToken(16);
    const createdAt = now().toISOString();
    store.insertClient({ id, name: parsed.data.client_name ?? "MCP client", redirectUris: parsed.data.redirect_uris, createdAt });
    return c.json(
      {
        client_id: id,
        client_name: parsed.data.client_name ?? "MCP client",
        redirect_uris: parsed.data.redirect_uris,
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_id_issued_at: Math.floor(Date.parse(createdAt) / 1000),
      },
      201,
    );
  });

  // ---- authorization: park the request and send the person to the app's connect screen ----
  app.get("/oauth/authorize", (c) => {
    const q = c.req.query();
    const client = store.getClient(q["client_id"] ?? "");
    const redirectUri = q["redirect_uri"] ?? "";
    if (!client || !client.redirectUris.includes(redirectUri)) return c.text("unknown client or redirect_uri", 400);
    const fail = (error: string) => {
      const u = new URL(redirectUri);
      u.searchParams.set("error", error);
      if (q["state"]) u.searchParams.set("state", q["state"]);
      return c.redirect(u.toString(), 302);
    };
    if (q["response_type"] !== "code") return fail("unsupported_response_type");
    if (!q["code_challenge"] || q["code_challenge_method"] !== "S256") return fail("invalid_request");
    const id = "req_" + randomToken(16);
    store.insertPending({ id, clientId: client.id, redirectUri, codeChallenge: q["code_challenge"], state: q["state"] ?? null, scope: q["scope"] ?? null, resource: q["resource"] ?? null, createdAt: now().toISOString() });
    return c.redirect(`${publicUrl}/#/connect-claude/${id}`, 302);
  });

  /** The app asks who is connecting, to show it on the consent screen. */
  app.get("/oauth/pending/:id", async (c) => {
    if (!(await opts.currentUserId(c.req.raw))) return c.json({ error: "unauthorized" }, 401);
    const p = store.peekPending(c.req.param("id"));
    if (!p || now().getTime() - Date.parse(p.createdAt) > PENDING_MAX_AGE_MS) return c.json({ error: "expired" }, 404);
    const client = store.getClient(p.clientId);
    return c.json({ id: p.id, clientName: client?.name ?? "MCP client", redirectHost: new URL(p.redirectUri).host });
  });

  /** The app finishes consent: hands over the credential (or denies). Requires the web session. */
  app.post("/oauth/approve", async (c) => {
    const userId = await opts.currentUserId(c.req.raw);
    if (!userId) return c.json({ error: "unauthorized" }, 401);
    const body = z.object({ id: z.string(), decision: z.enum(["approved", "denied"]), credential: z.string().max(16_384).optional() }).safeParse(await c.req.json().catch(() => ({})));
    if (!body.success) return c.json({ error: "bad_request" }, 400);
    const p = store.takePending(body.data.id, PENDING_MAX_AGE_MS);
    if (!p) return c.json({ error: "expired" }, 404);
    const redirect = new URL(p.redirectUri);
    if (p.state) redirect.searchParams.set("state", p.state);
    if (body.data.decision === "denied" || !body.data.credential) {
      redirect.searchParams.set("error", "access_denied");
      return c.json({ redirect: redirect.toString() });
    }
    let credential;
    try {
      credential = parseCredential(body.data.credential);
    } catch {
      return c.json({ error: "bad_credential" }, 400);
    }
    const connectionId = "con_" + randomToken(16);
    store.insertConnection({ id: connectionId, userId, serial: credential.card.credentialStatus.serial, clientId: p.clientId, createdAt: now().toISOString() }, JSON.stringify(credential));
    const code = randomToken(32);
    store.insertCode({ code, clientId: p.clientId, redirectUri: p.redirectUri, codeChallenge: p.codeChallenge, connectionId, resource: p.resource, expiresAt: now().getTime() + CODE_TTL_MS });
    redirect.searchParams.set("code", code);
    return c.json({ redirect: redirect.toString() });
  });

  // ---- token ----
  app.post("/oauth/token", async (c) => {
    const form = await c.req.parseBody().catch(() => ({}) as Record<string, unknown>);
    const get = (k: string) => (typeof form[k] === "string" ? (form[k] as string) : undefined);
    const grant = get("grant_type");
    const clientId = get("client_id") ?? "";
    const client = store.getClient(clientId);
    if (!client) return c.json({ error: "invalid_client" }, 401);
    const issue = (connectionId: string) => {
      const access = randomToken(32);
      const refresh = randomToken(32);
      const t = now().getTime();
      store.insertToken(access, { kind: "access", clientId, connectionId, expiresAt: t + ACCESS_TTL_MS });
      store.insertToken(refresh, { kind: "refresh", clientId, connectionId, expiresAt: t + REFRESH_TTL_MS });
      return c.json({ access_token: access, token_type: "bearer", expires_in: Math.floor(ACCESS_TTL_MS / 1000), refresh_token: refresh, scope: "agent" });
    };
    if (grant === "authorization_code") {
      const code = store.takeCode(get("code") ?? "");
      const verifier = get("code_verifier") ?? "";
      if (!code || code.clientId !== clientId || code.expiresAt < now().getTime()) return c.json({ error: "invalid_grant" }, 400);
      if (get("redirect_uri") && get("redirect_uri") !== code.redirectUri) return c.json({ error: "invalid_grant" }, 400);
      if (!verifier || s256(verifier) !== code.codeChallenge) return c.json({ error: "invalid_grant", error_description: "PKCE verification failed" }, 400);
      return issue(code.connectionId);
    }
    if (grant === "refresh_token") {
      const plain = get("refresh_token") ?? "";
      const row = store.getToken(plain);
      if (!row || row.kind !== "refresh" || row.clientId !== clientId || row.revokedAt || row.expiresAt < now().getTime()) return c.json({ error: "invalid_grant" }, 400);
      const conn = store.getConnection(row.connectionId);
      if (!conn || conn.revokedAt) return c.json({ error: "invalid_grant" }, 400);
      store.revokeToken(plain);
      return issue(row.connectionId);
    }
    return c.json({ error: "unsupported_grant_type" }, 400);
  });

  app.post("/oauth/revoke", async (c) => {
    const form = await c.req.parseBody().catch(() => ({}) as Record<string, unknown>);
    if (typeof form["token"] === "string") store.revokeToken(form["token"]);
    return c.body(null, 200);
  });

  // ---- connections, for the app ----
  app.get("/connections", async (c) => {
    const userId = await opts.currentUserId(c.req.raw);
    if (!userId) return c.json({ error: "unauthorized" }, 401);
    const list = store.connectionsForUser(userId).map((x) => ({ id: x.id, serial: x.serial, client: store.getClient(x.clientId)?.name ?? "MCP client", createdAt: x.createdAt, revokedAt: x.revokedAt }));
    return c.json({ connections: list });
  });
  app.post("/connections/:id/revoke", async (c) => {
    const userId = await opts.currentUserId(c.req.raw);
    if (!userId) return c.json({ error: "unauthorized" }, 401);
    const conn = store.getConnection(c.req.param("id"));
    if (!conn || conn.userId !== userId) return c.json({ error: "not_found" }, 404);
    store.revokeConnection(conn.id);
    runtimes.delete(conn.id);
    return c.json({ ok: true });
  });

  // ---- the MCP endpoint ----
  const unauthorized = (c: { json: (b: unknown, s: 401) => Response }) => {
    const res = c.json({ error: "unauthorized" }, 401);
    res.headers.set("WWW-Authenticate", `Bearer resource_metadata="${publicUrl}/.well-known/oauth-protected-resource/mcp"`);
    return res;
  };

  const runtimeFor = (connectionId: string): Promise<AgentRuntime> => {
    let rt = runtimes.get(connectionId);
    if (!rt) {
      const json = store.credentialFor(connectionId);
      if (!json) throw new Error("connection revoked");
      const credential = parseCredential(json);
      const o: Parameters<typeof AgentRuntime.create>[0] = { credential };
      if (opts.fetchFn) o.fetchFn = opts.fetchFn;
      rt = AgentRuntime.create(o);
      runtimes.set(connectionId, rt);
      rt.catch(() => runtimes.delete(connectionId));
    }
    return rt;
  };

  app.all("/mcp", async (c) => {
    const auth = c.req.header("authorization") ?? "";
    const m = /^Bearer\s+(\S+)$/i.exec(auth);
    if (!m) return unauthorized(c);
    const row = store.getToken(m[1] as string);
    if (!row || row.kind !== "access" || row.revokedAt || row.expiresAt < now().getTime()) return unauthorized(c);
    const conn = store.getConnection(row.connectionId);
    if (!conn || conn.revokedAt) return unauthorized(c);
    if (c.req.method === "DELETE") return c.body(null, 200);
    if (c.req.method !== "POST") return c.json({ error: "method_not_allowed" }, 405);
    let runtime: AgentRuntime;
    try {
      runtime = await runtimeFor(conn.id);
    } catch {
      return unauthorized(c);
    }
    // Stateless transport: one server instance per request, no session ids to manage.
    const server = createMcpServer(runtime);
    const transport = new WebStandardStreamableHTTPServerTransport({});
    await server.connect(transport);
    return transport.handleRequest(c.req.raw, { authInfo: { token: m[1] as string, clientId: conn.clientId, scopes: ["agent"], expiresAt: Math.floor(row.expiresAt / 1000) } });
  });

  return app;
}
