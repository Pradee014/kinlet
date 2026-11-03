/**
 * Passkey routes. Registration creates the user; login and "reauth" both verify an assertion with
 * user verification required. "reauth" refreshes lastAuthAt, which the client checks before any
 * signing with the root key (the passkey gesture gate, control C1 in the threat model).
 */
import { Hono, type Context } from "hono";
import { randomBytes } from "node:crypto";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticatorTransportFuture,
} from "@simplewebauthn/server";
import { z } from "zod";
import type { WebStore } from "./store.js";

export interface AuthDeps {
  store: WebStore;
  rpId: string;
  rpName: string;
  origin: string;
  getSession: (c: Context) => string | undefined;
  setSession: (c: Context, id: string) => void;
  clearSession: (c: Context) => void;
}

const USERNAME = z.string().regex(/^[a-z0-9][a-z0-9._-]{1,31}$/i, "2-32 letters, digits, . _ -");
const CHALLENGE_TTL_MS = 5 * 60_000;
const FRESH_AUTH_MS = 5 * 60_000;

export function createAuthRoutes(deps: AuthDeps): Hono {
  const { store } = deps;
  const app = new Hono();

  const currentUser = (c: Context) => {
    const sid = deps.getSession(c);
    if (!sid) return undefined;
    const s = store.getSession(sid);
    if (!s) return undefined;
    const u = store.getUser(s.userId);
    return u ? { user: u, session: s } : undefined;
  };

  app.get("/session", (c) => {
    const cu = currentUser(c);
    if (!cu) return c.json({ user: null });
    const fresh = Date.now() - Date.parse(cu.session.lastAuthAt) < FRESH_AUTH_MS;
    return c.json({ user: { id: cu.user.id, username: cu.user.username }, freshAuth: fresh, freshAuthWindowMs: FRESH_AUTH_MS });
  });

  app.post("/logout", (c) => {
    const sid = deps.getSession(c);
    if (sid) store.deleteSession(sid);
    deps.clearSession(c);
    return c.json({ ok: true });
  });

  // ---- Registration ----
  app.post("/register/options", async (c) => {
    const body = z.object({ username: USERNAME }).safeParse(await c.req.json().catch(() => ({})));
    if (!body.success) return c.json({ error: "bad_username" }, 400);
    const username = body.data.username.toLowerCase();
    if (store.getUserByName(username)) return c.json({ error: "username_taken" }, 409);
    const options = await generateRegistrationOptions({
      rpName: deps.rpName,
      rpID: deps.rpId,
      userName: username,
      userDisplayName: username,
      attestationType: "none",
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      supportedAlgorithmIDs: [-8, -7, -257],
    });
    store.putChallenge("reg:" + username, options.challenge, CHALLENGE_TTL_MS);
    return c.json(options);
  });

  app.post("/register/verify", async (c) => {
    const body = z.object({ username: USERNAME, response: z.any() }).safeParse(await c.req.json().catch(() => ({})));
    if (!body.success) return c.json({ error: "bad_request" }, 400);
    const username = body.data.username.toLowerCase();
    const expectedChallenge = store.takeChallenge("reg:" + username);
    if (!expectedChallenge) return c.json({ error: "challenge_expired" }, 400);
    if (store.getUserByName(username)) return c.json({ error: "username_taken" }, 409);
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: body.data.response,
        expectedChallenge,
        expectedOrigin: deps.origin,
        expectedRPID: deps.rpId,
        requireUserVerification: true,
      });
    } catch (e) {
      return c.json({ error: "verification_failed", detail: e instanceof Error ? e.message : String(e) }, 400);
    }
    if (!verification.verified || !verification.registrationInfo) return c.json({ error: "verification_failed" }, 400);
    const { credential } = verification.registrationInfo;
    const now = new Date().toISOString();
    const userId = randomBytes(16).toString("base64url");
    store.insertUser({ id: userId, username, createdAt: now });
    store.insertPasskey({ id: credential.id, userId, publicKey: credential.publicKey, counter: credential.counter, transports: credential.transports ? JSON.stringify(credential.transports) : null, createdAt: now });
    const sid = randomBytes(32).toString("base64url");
    store.insertSession({ id: sid, userId, createdAt: now, lastAuthAt: now });
    deps.setSession(c, sid);
    return c.json({ ok: true, user: { id: userId, username } });
  });

  // ---- Login and re-authentication (same ceremony; reauth keeps the session) ----
  const loginOptions = async (c: Context, username: string | undefined) => {
    const allowCredentials = username
      ? store.passkeysFor(store.getUserByName(username)?.id ?? "").map((p) => {
          const entry: { id: string; transports?: AuthenticatorTransportFuture[] } = { id: p.id };
          if (p.transports) entry.transports = JSON.parse(p.transports) as AuthenticatorTransportFuture[];
          return entry;
        })
      : [];
    const options = await generateAuthenticationOptions({ rpID: deps.rpId, userVerification: "required", allowCredentials });
    const key = "login:" + randomBytes(12).toString("base64url");
    store.putChallenge(key, options.challenge, CHALLENGE_TTL_MS);
    return c.json({ options, key });
  };

  app.post("/login/options", async (c) => {
    const body = z.object({ username: USERNAME.optional() }).safeParse(await c.req.json().catch(() => ({})));
    if (!body.success) return c.json({ error: "bad_request" }, 400);
    return loginOptions(c, body.data.username?.toLowerCase());
  });

  app.post("/login/verify", async (c) => {
    const body = z.object({ key: z.string(), response: z.any() }).safeParse(await c.req.json().catch(() => ({})));
    if (!body.success) return c.json({ error: "bad_request" }, 400);
    const expectedChallenge = store.takeChallenge(body.data.key);
    if (!expectedChallenge) return c.json({ error: "challenge_expired" }, 400);
    const credId = (body.data.response as { id?: string }).id ?? "";
    const passkey = store.getPasskey(credId);
    if (!passkey) return c.json({ error: "unknown_passkey" }, 400);
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body.data.response,
        expectedChallenge,
        expectedOrigin: deps.origin,
        expectedRPID: deps.rpId,
        requireUserVerification: true,
        credential: {
          id: passkey.id,
          publicKey: new Uint8Array(passkey.publicKey) as Uint8Array<ArrayBuffer>,
          counter: passkey.counter,
          ...(passkey.transports ? { transports: JSON.parse(passkey.transports) as AuthenticatorTransportFuture[] } : {}),
        },
      });
    } catch (e) {
      return c.json({ error: "verification_failed", detail: e instanceof Error ? e.message : String(e) }, 400);
    }
    if (!verification.verified) return c.json({ error: "verification_failed" }, 400);
    store.updateCounter(passkey.id, verification.authenticationInfo.newCounter);
    const now = new Date().toISOString();
    const existing = currentUser(c);
    if (existing && existing.user.id === passkey.userId) {
      store.touchSession(existing.session.id, now);
    } else {
      const sid = randomBytes(32).toString("base64url");
      store.insertSession({ id: sid, userId: passkey.userId, createdAt: now, lastAuthAt: now });
      deps.setSession(c, sid);
    }
    const user = store.getUser(passkey.userId)!;
    return c.json({ ok: true, user: { id: user.id, username: user.username }, freshAuth: true });
  });

  return app;
}
