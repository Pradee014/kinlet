/**
 * The agent runtime: holds the agent key and card, signs requests, obtains approvals through the
 * directory relay, and reports every attempt to the activity chain. Transport-agnostic so it can
 * be unit-tested without MCP.
 */
import { z } from "zod";
import {
  approvalRequestFor,
  base64urlDecode,
  CardSchema,
  eventHash,
  GENESIS_HASH,
  importPrivateKeyWithPublic,
  newNonce,
  signDocument,
  signEvent,
  signRequest,
  toMinorUnits,
  utf8Decode,
  type ActionSpec,
  type Card,
  type KeyPair,
} from "@kinlet/core";
import { MONETARY_ACTIONS } from "@kinlet/core";

/** The credential the web app hands to the agent runtime, once. */
export const AgentCredentialSchema = z
  .object({
    version: z.literal(1),
    card: CardSchema,
    agent: z.object({ publicKey: z.string(), privateKeyPkcs8: z.string() }).strict(),
  })
  .strict();
export type AgentCredential = z.infer<typeof AgentCredentialSchema>;

export interface RuntimeState {
  seq: number;
  prev: string;
}

export interface RuntimeOptions {
  credential: AgentCredential;
  fetchFn?: typeof fetch;
  /** Persisted event-chain state; defaults to in-memory. */
  state?: { load(): Promise<RuntimeState | null>; save(s: RuntimeState): Promise<void> };
  now?: () => Date;
  /** How long to wait for the person to answer an approval request. */
  approvalTimeoutMs?: number;
  approvalPollMs?: number;
}

export interface ActInput {
  url: string;
  method?: string;
  action: ActionSpec;
  body?: string;
  /** If false, a 402 is returned to the caller instead of waiting for the person. */
  waitForApproval?: boolean;
}

export interface ActResult {
  status: number;
  ok: boolean;
  reason?: string;
  body: string;
  approvalRequested?: boolean;
  approvalOutcome?: "approved" | "denied" | "timeout";
}

export class AgentRuntime {
  private agent!: KeyPair;
  private readonly card: Card;
  private readonly fetchFn: typeof fetch;
  private readonly now: () => Date;
  private state: RuntimeState = { seq: 0, prev: GENESIS_HASH };
  private readonly stateStore: NonNullable<RuntimeOptions["state"]>;
  private readonly approvalTimeoutMs: number;
  private readonly approvalPollMs: number;
  private readonly directory: string;

  private constructor(private readonly opts: RuntimeOptions) {
    this.card = opts.credential.card;
    this.fetchFn = opts.fetchFn ?? fetch;
    this.now = opts.now ?? (() => new Date());
    this.stateStore = opts.state ?? memoryState();
    this.approvalTimeoutMs = opts.approvalTimeoutMs ?? 120_000;
    this.approvalPollMs = opts.approvalPollMs ?? 1500;
    this.directory = this.card.credentialStatus.directory.replace(/\/$/, "");
  }

  static async create(opts: RuntimeOptions): Promise<AgentRuntime> {
    const rt = new AgentRuntime(opts);
    const { agent } = opts.credential;
    rt.agent = await importPrivateKeyWithPublic(base64urlDecode(agent.privateKeyPkcs8), base64urlDecode(agent.publicKey));
    if (rt.agent.did !== rt.card.credentialSubject.id) throw new Error("agent key does not match the card");
    const saved = await rt.stateStore.load();
    if (saved) rt.state = saved;
    return rt;
  }

  /** What the model is allowed to know about the card. No keys. */
  summary(): Record<string, unknown> {
    const c = this.card;
    return {
      name: c.credentialSubject.name,
      serial: c.credentialStatus.serial,
      owner: c.issuer,
      agent: c.credentialSubject.id,
      validUntil: c.validUntil,
      permissions: c.credentialSubject.permissions,
      directory: c.credentialStatus.directory,
    };
  }

  /** Local pre-check so the model gets a clear answer before a network call. */
  precheck(input: ActInput): { ok: true; needsApproval: boolean } | { ok: false; reason: string } {
    const p = this.card.credentialSubject.permissions;
    let origin: string;
    try {
      origin = new URL(input.url).origin;
    } catch {
      return { ok: false, reason: "bad_url" };
    }
    if (!p.services.includes(origin)) return { ok: false, reason: "service_not_allowed" };
    if (!p.actions.includes(input.action.type)) return { ok: false, reason: "action_not_allowed" };
    let needsApproval = p.approval?.forActions?.includes(input.action.type) ?? false;
    if (MONETARY_ACTIONS.has(input.action.type)) {
      if (!p.limits || typeof input.action.amount !== "number" || input.action.currency !== p.limits.currency) return { ok: false, reason: "limit_exceeded" };
      if (toMinorUnits(input.action.amount) > toMinorUnits(p.limits.perAction)) return { ok: false, reason: "limit_exceeded" };
      if (p.approval?.above !== undefined && toMinorUnits(input.action.amount) >= toMinorUnits(p.approval.above)) needsApproval = true;
    }
    return { ok: true, needsApproval };
  }

  async act(input: ActInput): Promise<ActResult> {
    const method = (input.method ?? (input.body ? "POST" : "GET")).toUpperCase();
    const pre = this.precheck(input);
    if (!pre.ok) {
      await this.report(input, `refused:${pre.reason}`);
      return { status: 0, ok: false, reason: pre.reason, body: "" };
    }

    const nonce = newNonce();
    let approval: string | undefined;
    let approvalRequested = false;
    let approvalOutcome: ActResult["approvalOutcome"];
    if (pre.needsApproval) {
      if (input.waitForApproval === false) {
        await this.report(input, "refused:approval_required");
        return { status: 402, ok: false, reason: "approval_required", body: "" };
      }
      approvalRequested = true;
      const got = await this.obtainApproval(input, nonce);
      approvalOutcome = got.outcome;
      if (got.outcome !== "approved") {
        await this.report(input, got.outcome === "denied" ? "refused:approval_denied" : "refused:approval_timeout");
        return { status: 402, ok: false, reason: got.outcome === "denied" ? "approval_denied" : "approval_timeout", body: "", approvalRequested, approvalOutcome };
      }
      approval = got.token;
    }

    const signInput: Parameters<typeof signRequest>[0] = { agent: this.agent, card: this.card, method, url: input.url, action: input.action, nonce, now: this.now() };
    if (input.body !== undefined) signInput.body = input.body;
    if (approval) signInput.approval = approval;
    const signed = await signRequest(signInput);
    const init: RequestInit = { method, headers: { ...signed.headers, "content-type": "application/json" } };
    if (input.body !== undefined && method !== "GET" && method !== "HEAD") init.body = input.body;

    let res: Response;
    try {
      res = await this.fetchFn(input.url, init);
    } catch (e) {
      await this.report(input, "error");
      return { status: 0, ok: false, reason: "network_error", body: e instanceof Error ? e.message : String(e), approvalRequested, ...(approvalOutcome ? { approvalOutcome } : {}) };
    }
    const text = await res.text();
    let reason: string | undefined;
    if (!res.ok) {
      try {
        const j = JSON.parse(text) as { error?: unknown };
        if (typeof j.error === "string") reason = j.error;
      } catch {
        /* non-JSON error body */
      }
    }
    await this.report(input, res.ok ? "ok" : reason && /^[a-z_]+$/.test(reason) ? `refused:${reason}` : "error");
    const out: ActResult = { status: res.status, ok: res.ok, body: text.slice(0, 16_384) };
    if (reason) out.reason = reason;
    if (approvalRequested) out.approvalRequested = true;
    if (approvalOutcome) out.approvalOutcome = approvalOutcome;
    return out;
  }

  private async obtainApproval(input: ActInput, nonce: string): Promise<{ outcome: "approved"; token: string } | { outcome: "denied" | "timeout" }> {
    const req = approvalRequestFor(this.card, input.url, input.action, nonce);
    const doc = { type: "KinletApprovalRequest" as const, ...req, at: this.now().toISOString() };
    const signed = await signDocument(doc, this.agent, { created: this.now() });
    const serial = this.card.credentialStatus.serial;
    const created = await this.fetchFn(`${this.directory}/v1/cards/${serial}/approvals`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(signed) });
    if (!created.ok) return { outcome: "timeout" };
    const { id } = (await created.json()) as { id: string };
    const deadline = this.now().getTime() + this.approvalTimeoutMs;
    while (this.now().getTime() < deadline) {
      await new Promise((r) => setTimeout(r, this.approvalPollMs));
      const res = await this.fetchFn(`${this.directory}/v1/approvals/${id}`);
      if (!res.ok) continue;
      const j = (await res.json()) as { status: string; token?: string | null };
      if (j.status === "approved" && j.token) return { outcome: "approved", token: j.token };
      if (j.status === "denied") return { outcome: "denied" };
    }
    return { outcome: "timeout" };
  }

  /** Appends to the activity chain. Resyncs from the directory's expected seq/prev on mismatch. */
  private async report(input: ActInput, outcome: string): Promise<void> {
    const serial = this.card.credentialStatus.serial;
    const target = new URL(input.url);
    target.hash = "";
    target.search = "";
    const attempt = async (): Promise<Response> => {
      const ev = await signEvent({ serial, seq: this.state.seq, prev: this.state.prev, target: target.toString(), action: input.action, outcome }, this.agent, this.now());
      const res = await this.fetchFn(`${this.directory}/v1/cards/${serial}/events`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(ev) });
      if (res.ok) {
        this.state = { seq: this.state.seq + 1, prev: await eventHash(ev) };
        await this.stateStore.save(this.state);
      }
      return res;
    };
    try {
      const res = await attempt();
      if (res.status === 400) {
        const j = (await res.json()) as { expectedSeq?: number; expectedPrev?: string };
        if (typeof j.expectedSeq === "number" && typeof j.expectedPrev === "string") {
          this.state = { seq: j.expectedSeq, prev: j.expectedPrev };
          await attempt();
        }
      }
    } catch {
      // Reporting must never block the action; the directory's gap detection covers lost events.
    }
  }
}

function memoryState(): NonNullable<RuntimeOptions["state"]> {
  let s: RuntimeState | null = null;
  return { load: async () => s, save: async (v) => void (s = v) };
}

export function parseCredential(raw: string): AgentCredential {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    json = JSON.parse(utf8Decode(base64urlDecode(raw.trim())));
  }
  const parsed = AgentCredentialSchema.safeParse(json);
  if (!parsed.success) throw new Error("invalid agent credential: " + parsed.error.issues.map((i) => i.path.join(".") + " " + i.message).join("; "));
  return parsed.data;
}
