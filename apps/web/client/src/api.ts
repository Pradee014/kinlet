/** Server (passkeys/session) and directory calls. */
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { createOwnerProof, type Signer } from "@kinlet/core";

export interface Config {
  directoryUrl: string;
  merchantUrl: string;
  rpId: string;
  origin: string;
}

export interface SessionInfo {
  user: { id: string; username: string } | null;
  freshAuth?: boolean;
  freshAuthWindowMs?: number;
}

async function j<T>(res: Response): Promise<T> {
  const body = (await res.json().catch(() => ({}))) as T & { error?: string; detail?: string };
  if (!res.ok) throw new Error(body.error ? `${body.error}${body.detail ? ": " + body.detail : ""}` : `HTTP ${res.status}`);
  return body;
}

const post = (url: string, body: unknown, headers: Record<string, string> = {}) =>
  fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body), credentials: "same-origin" });

export const server = {
  config: () => fetch("/config").then((r) => j<Config>(r)),
  session: () => fetch("/auth/session", { credentials: "same-origin" }).then((r) => j<SessionInfo>(r)),
  logout: () => post("/auth/logout", {}).then((r) => j<unknown>(r)),

  async register(username: string): Promise<SessionInfo> {
    const options = await j<Parameters<typeof startRegistration>[0]["optionsJSON"]>(await post("/auth/register/options", { username }));
    const response = await startRegistration({ optionsJSON: options });
    const out = await j<{ user: SessionInfo["user"] }>(await post("/auth/register/verify", { username, response }));
    return { user: out.user, freshAuth: true };
  },

  /** Login (no session) or re-authentication (existing session). Both are a passkey gesture. */
  async passkey(username?: string): Promise<SessionInfo> {
    const { options, key } = await j<{ options: Parameters<typeof startAuthentication>[0]["optionsJSON"]; key: string }>(await post("/auth/login/options", username ? { username } : {}));
    const response = await startAuthentication({ optionsJSON: options });
    const out = await j<{ user: SessionInfo["user"] }>(await post("/auth/login/verify", { key, response }));
    return { user: out.user, freshAuth: true };
  },
};

export function directory(base: string) {
  const root = base.replace(/\/$/, "");
  const owned = async (signer: Signer, path: string, init: RequestInit = {}) => {
    const proof = await createOwnerProof(signer);
    return fetch(root + path, { ...init, headers: { ...(init.headers as Record<string, string> | undefined), "kinlet-owner-proof": proof } });
  };
  return {
    wellKnown: () => fetch(root + "/.well-known/kinlet.json").then((r) => j<{ did: string }>(r)),
    register: (card: unknown) => post(root + "/v1/cards", card).then((r) => j<{ status: string }>(r)),
    status: (serial: string) => fetch(root + `/v1/cards/${serial}/status`).then((r) => j<{ status: "valid" | "revoked" | "unknown" }>(r)),
    revoke: (serial: string, revocation: unknown) => post(root + `/v1/cards/${serial}/revoke`, revocation).then((r) => j<{ status: string }>(r)),
    cards: (owner: Signer) => owned(owner, `/v1/issuers/${encodeURIComponent(owner.did)}/cards`).then((r) => j<{ cards: { serial: string; status: string; validUntil: string }[] }>(r)),
    events: (owner: Signer, serial: string) => owned(owner, `/v1/cards/${serial}/events`).then((r) => j<{ events: EventView[] }>(r)),
    pendingApprovals: (owner: Signer) => owned(owner, `/v1/issuers/${encodeURIComponent(owner.did)}/approvals`).then((r) => j<{ pending: PendingApproval[] }>(r)),
    answerApproval: (owner: Signer, id: string, body: { decision: "approved" | "denied"; token?: string }) =>
      owned(owner, `/v1/approvals/${id}/answer`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).then((r) => j<unknown>(r)),
  };
}

export interface EventView {
  seq: number;
  at: string;
  target: string;
  action: { type: string; amount?: number; currency?: string; ref?: string };
  outcome: string;
}

export interface PendingApproval {
  id: string;
  serial: string;
  createdAt: string;
  request: { card: string; target: string; action: { type: string; amount?: number; currency?: string; ref?: string }; nonce: string; at: string };
}
