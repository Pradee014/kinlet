import {
  base64urlEncode,
  createApproval,
  exportPrivateKeyOnce,
  generateKeyPair,
  issueCard,
  signRevocation,
  STANDARD_ACTIONS,
  utf8Encode,
  type Card,
  type Permissions,
  type Signer,
} from "@kinlet/core";
import { directory, server, type Config, type PendingApproval, type SessionInfo } from "./api.js";
import { agents, loadOrCreateRootKey, type RootKey } from "./keys.js";
import { describeAction, describeOutcome, money, when } from "./text.js";

// ---------- state ----------

interface State {
  config: Config;
  session: SessionInfo;
  root?: RootKey;
  dir: ReturnType<typeof directory>;
  pending: PendingApproval[];
}

let state: State;
/** Credentials shown once on the connect screen; cleared when the person confirms they saved it. */
const freshCredentials = new Map<string, string>();

const app = document.getElementById("app") as HTMLDivElement;

function esc(s: unknown): string {
  return String(s).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch] as string);
}

function render(html: string): void {
  app.innerHTML = html;
}

function go(hash: string): void {
  location.hash = hash;
}

function err(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** The passkey gate: every root-key use first checks for a recent passkey gesture. */
async function gate(): Promise<void> {
  const s = await server.session();
  if (!s.user) throw new Error("signed out");
  if (!s.freshAuth) await server.passkey(s.user.username);
}

function owner(): Signer {
  if (!state.root) throw new Error("no root key");
  return state.root.withGate(gate);
}

/** Owner proofs for reads should not prompt for a passkey; reads are not sensitive signing. */
function reader(): Signer {
  if (!state.root) throw new Error("no root key");
  return state.root.withGate(async () => {});
}

// ---------- screens ----------

async function screenSignIn(message = ""): Promise<void> {
  render(`
    <h1>Kinlet</h1>
    <p>Give your AI agent an ID card. You stay in control: the card says what it may do, and you can cancel it with one tap.</p>
    <div class="card">
      <label for="u">Username</label>
      <input id="u" autocomplete="username webauthn" autocapitalize="off" placeholder="e.g. pradeep" />
      <p class="muted">Your account is protected by a passkey (Face ID, fingerprint, or your device PIN). No password.</p>
      <div class="row" style="margin-top:10px">
        <button id="reg" class="primary">Create account</button>
        <button id="login">Sign in</button>
      </div>
      <p id="msg" class="err">${esc(message)}</p>
    </div>`);
  const u = document.getElementById("u") as HTMLInputElement;
  const msg = document.getElementById("msg") as HTMLParagraphElement;
  const run = async (fn: () => Promise<SessionInfo>) => {
    msg.textContent = "";
    try {
      state.session = await fn();
      await afterSignIn();
    } catch (e) {
      msg.textContent = err(e);
    }
  };
  document.getElementById("reg")!.onclick = () => run(() => server.register(u.value.trim()));
  document.getElementById("login")!.onclick = () => run(() => server.passkey(u.value.trim() || undefined));
}

async function afterSignIn(): Promise<void> {
  const user = state.session.user;
  if (!user) return screenSignIn();
  state.root = await loadOrCreateRootKey(user.id);
  go("#/");
  void pollApprovals();
}

function nav(): string {
  const user = state.session.user;
  return `<div class="nav"><a href="#/">Agents</a><span class="muted">·</span><span class="muted">${esc(user?.username ?? "")}</span><span style="flex:1"></span><button id="logout" class="muted" style="padding:4px 8px">Sign out</button></div>`;
}

function bindNav(): void {
  const b = document.getElementById("logout");
  if (b) b.onclick = async () => {
    await server.logout();
    state.session = { user: null };
    go("#/");
    await route();
  };
}

function approvalsBanner(): string {
  if (!state.pending.length) return "";
  const n = state.pending.length;
  return `<div class="banner row"><span>${n === 1 ? "Your agent is asking for approval" : `${n} approvals waiting`}</span><button id="openApprovals">Review</button></div>`;
}

function bindBanner(): void {
  const b = document.getElementById("openApprovals");
  if (b) b.onclick = () => go("#/approvals");
}

async function screenHome(): Promise<void> {
  const list = await agents.all();
  let statuses = new Map<string, string>();
  try {
    const { cards } = await state.dir.cards(reader());
    statuses = new Map(cards.map((c) => [c.serial, c.status]));
  } catch {
    /* directory offline: show cards without status */
  }
  const items = list
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .map((a) => {
      const card = a.card as Card;
      const st = statuses.get(a.serial) ?? "unknown";
      const expired = Date.parse(card.validUntil) < Date.now();
      const pill = st === "revoked" ? `<span class="pill bad">cancelled</span>` : expired ? `<span class="pill bad">expired</span>` : st === "valid" ? `<span class="pill ok">active</span>` : `<span class="pill">status unknown</span>`;
      return `<a class="card row" href="#/agent/${a.serial}" style="text-decoration:none;color:inherit"><div><strong>${esc(card.credentialSubject.name)}</strong><div class="muted">${esc(card.credentialSubject.permissions.services.map((s) => new URL(s).host).join(", "))}</div></div>${pill}</a>`;
    })
    .join("");
  render(`${nav()}${approvalsBanner()}<h1>Your agents</h1>${items || `<p class="muted">No agents yet. Create one to give an AI an ID card.</p>`}<p><button id="new" class="primary">+ Create agent</button></p>
  <p class="muted">Your ID: <code>${esc(state.root?.did.slice(0, 24))}…</code> (kept on this device)</p>`);
  bindNav();
  bindBanner();
  document.getElementById("new")!.onclick = () => go("#/new");
}

const TEMPLATES: Record<string, { label: string; perms: (service: string) => Permissions }> = {
  shopping: {
    label: "Shopping — buy small things, ask me above a limit",
    perms: (service) => ({ services: [service], actions: ["read", "purchase", "cancel"], limits: { currency: "USD", perAction: 50, perDay: 100 }, approval: { above: 20, forActions: ["cancel"] } }),
  },
  reader: { label: "Reader — look things up, never pay", perms: (service) => ({ services: [service], actions: ["read"] }) },
  cautious: {
    label: "Cautious — ask me before every purchase",
    perms: (service) => ({ services: [service], actions: ["read", "purchase"], limits: { currency: "USD", perAction: 25, perDay: 50 }, approval: { above: 0 } }),
  },
};

async function screenNew(): Promise<void> {
  const actionBoxes = STANDARD_ACTIONS.map((a) => `<label style="display:inline-block;margin-right:12px"><input type="checkbox" name="act" value="${a}" style="width:auto"/> ${a}</label>`).join("");
  render(`${nav()}<h1>Create agent</h1>
  <div class="card">
    <label>Name</label><input id="name" placeholder="Shopping agent" maxlength="80"/>
    <label>Template</label><select id="tpl">${Object.entries(TEMPLATES).map(([k, t]) => `<option value="${k}">${esc(t.label)}</option>`).join("")}<option value="custom">Custom</option></select>
    <label>Allowed service (origin)</label><input id="service" value="${esc(state.config.merchantUrl)}"/>
    <div id="custom" style="display:none">
      <label>Actions</label><div>${actionBoxes}</div>
      <label>Currency</label><input id="cur" value="USD" maxlength="3"/>
      <label>Max per action</label><input id="perAction" type="number" step="0.01" value="50"/>
      <label>Max per day</label><input id="perDay" type="number" step="0.01" value="100"/>
      <label>Ask me first at or above</label><input id="above" type="number" step="0.01" value="20"/>
    </div>
    <label>Valid for (days, max 90)</label><input id="days" type="number" value="30" min="1" max="90"/>
    <p class="muted">Creating the card needs your passkey. The agent's own key is made here and handed over once on the next screen.</p>
    <div class="row"><button id="create" class="primary">Create card</button><a href="#/">Cancel</a></div>
    <p id="msg" class="err"></p>
  </div>`);
  bindNav();
  const tpl = document.getElementById("tpl") as HTMLSelectElement;
  const custom = document.getElementById("custom") as HTMLDivElement;
  tpl.onchange = () => (custom.style.display = tpl.value === "custom" ? "block" : "none");
  const msg = document.getElementById("msg") as HTMLParagraphElement;
  const val = (id: string) => (document.getElementById(id) as HTMLInputElement).value.trim();

  document.getElementById("create")!.onclick = async () => {
    msg.textContent = "";
    const btn = document.getElementById("create") as HTMLButtonElement;
    btn.disabled = true;
    try {
      const name = val("name") || "My agent";
      const service = new URL(val("service")).origin;
      let permissions: Permissions;
      if (tpl.value === "custom") {
        const actions = Array.from(document.querySelectorAll<HTMLInputElement>('input[name="act"]:checked')).map((i) => i.value);
        const limits = { currency: val("cur").toUpperCase(), perAction: Number(val("perAction")), perDay: Number(val("perDay")) };
        permissions = { services: [service], actions, limits, approval: { above: Number(val("above")) } };
      } else {
        permissions = TEMPLATES[tpl.value]!.perms(service);
      }
      const days = Math.min(90, Math.max(1, Number(val("days")) || 30));
      const agentKey = await generateKeyPair({ extractable: true });
      const card = await issueCard({ issuer: owner(), agentDid: agentKey.did, name, permissions, directory: state.config.directoryUrl, validUntil: new Date(Date.now() + days * 86_400_000) });
      await state.dir.register(card);
      const credential = { version: 1, card, agent: { publicKey: base64urlEncode(agentKey.publicKey), privateKeyPkcs8: base64urlEncode(await exportPrivateKeyOnce(agentKey)) } };
      freshCredentials.set(card.credentialStatus.serial, base64urlEncode(utf8Encode(JSON.stringify(credential))));
      await agents.put({ serial: card.credentialStatus.serial, card, createdAt: new Date().toISOString() });
      go(`#/connect/${card.credentialStatus.serial}`);
    } catch (e) {
      msg.textContent = err(e);
      btn.disabled = false;
    }
  };
}

async function screenConnect(serial: string): Promise<void> {
  const cred = freshCredentials.get(serial);
  const a = await agents.get(serial);
  if (!a) return go("#/");
  const card = a.card as Card;
  if (!cred) {
    render(`${nav()}<h1>${esc(card.credentialSubject.name)}</h1><p>The connection code for this agent was shown once and is gone. If you lost it, cancel this card and create a new agent.</p><p><a href="#/agent/${serial}">Back to the agent</a></p>`);
    bindNav();
    return;
  }
  const claudeDesktop = JSON.stringify({ mcpServers: { kinlet: { command: "npx", args: ["-y", "@kinlet/mcp"], env: { KINLET_AGENT: "<paste the code>" } } } }, null, 2);
  render(`${nav()}<h1>Connect ${esc(card.credentialSubject.name)}</h1>
  <div class="card">
    <p><strong>This code is shown once.</strong> It is the agent's own key plus its card. Paste it into your AI tool, then come back and tap "I saved it".</p>
    <pre id="code">${esc(cred)}</pre>
    <div class="row"><button id="copy" class="primary">Copy code</button><button id="dl">Download file</button></div>
  </div>
  <h2>Where to paste it</h2>
  <div class="card"><h3>Claude Code</h3><pre>claude mcp add kinlet -e KINLET_AGENT=&lt;paste the code&gt; -- npx -y @kinlet/mcp</pre></div>
  <div class="card"><h3>Claude Desktop, Cursor, other MCP apps</h3><pre>${esc(claudeDesktop)}</pre></div>
  <p><button id="done" class="primary">I saved it</button></p>`);
  bindNav();
  document.getElementById("copy")!.onclick = () => navigator.clipboard.writeText(cred);
  document.getElementById("dl")!.onclick = () => {
    const blob = new Blob([cred], { type: "text/plain" });
    const a2 = document.createElement("a");
    a2.href = URL.createObjectURL(blob);
    a2.download = `kinlet-agent-${serial}.txt`;
    a2.click();
  };
  document.getElementById("done")!.onclick = () => {
    freshCredentials.delete(serial);
    go(`#/agent/${serial}`);
  };
}

async function screenAgent(serial: string): Promise<void> {
  const a = await agents.get(serial);
  if (!a) return go("#/");
  const card = a.card as Card;
  const p = card.credentialSubject.permissions;
  let status = "unknown";
  let events: Awaited<ReturnType<typeof state.dir.events>>["events"] = [];
  let dirError = "";
  try {
    status = (await state.dir.status(serial)).status;
    events = (await state.dir.events(reader(), serial)).events;
  } catch (e) {
    dirError = err(e);
  }
  const revoked = status === "revoked";
  const rules = [
    `May use: ${p.services.map((s) => new URL(s).host).join(", ")}`,
    `May: ${p.actions.join(", ")}`,
    p.limits ? `Spend up to ${money(p.limits.perAction, p.limits.currency)} per action, ${money(p.limits.perDay, p.limits.currency)} per day` : "Cannot spend money",
    p.approval?.above !== undefined ? `Asks you first at or above ${money(p.approval.above, p.limits?.currency)}` : "",
    p.approval?.forActions?.length ? `Always asks before: ${p.approval.forActions.join(", ")}` : "",
    `Valid until ${when(card.validUntil)}`,
  ].filter(Boolean);
  const feed = events
    .slice()
    .reverse()
    .map((e) => {
      const o = describeOutcome(e.outcome);
      return `<li><div>${esc(describeAction(e.action, e.target))}</div><div class="muted">${esc(when(e.at))} · <span class="${o.good ? "ok" : "err"}">${esc(o.text)}</span></div></li>`;
    })
    .join("");
  render(`${nav()}${approvalsBanner()}<h1>${esc(card.credentialSubject.name)} ${revoked ? '<span class="pill bad">cancelled</span>' : status === "valid" ? '<span class="pill ok">active</span>' : '<span class="pill">status unknown</span>'}</h1>
  <div class="card"><ul>${rules.map((r) => `<li>${esc(r)}</li>`).join("")}</ul><p class="muted">Card ${esc(serial)}</p></div>
  ${revoked ? "" : `<p><button id="revoke" class="danger">Cancel this card</button> <span class="muted">Takes effect everywhere immediately.</span></p>`}
  <h2>Activity</h2>${dirError ? `<p class="err">Could not load activity: ${esc(dirError)}</p>` : ""}
  <ul class="feed">${feed || '<li class="muted">Nothing yet.</li>'}</ul>
  <p id="msg" class="err"></p>`);
  bindNav();
  bindBanner();
  const r = document.getElementById("revoke") as HTMLButtonElement | null;
  if (r)
    r.onclick = async () => {
      if (!confirm(`Cancel the card for "${card.credentialSubject.name}"? The agent will be refused everywhere from now on. This cannot be undone.`)) return;
      r.disabled = true;
      try {
        const rev = await signRevocation({ serial, reason: "cancelled by owner" }, owner());
        await state.dir.revoke(serial, rev);
        await screenAgent(serial);
      } catch (e) {
        (document.getElementById("msg") as HTMLParagraphElement).textContent = err(e);
        r.disabled = false;
      }
    };
}

async function screenApprovals(): Promise<void> {
  await refreshPending();
  const items = await Promise.all(
    state.pending.map(async (pa) => {
      const a = await agents.get(pa.serial);
      const name = a ? (a.card as Card).credentialSubject.name : pa.serial;
      return `<div class="card"><div class="muted">${esc(name)} asks</div><p><strong>${esc(describeAction(pa.request.action, pa.request.target))}</strong></p><div class="muted">${esc(when(pa.createdAt))}</div>
      <div class="row" style="margin-top:8px"><button class="primary" data-approve="${pa.id}">Approve</button><button data-deny="${pa.id}">Deny</button></div></div>`;
    }),
  );
  render(`${nav()}<h1>Approvals</h1>${items.join("") || '<p class="muted">Nothing waiting.</p>'}<p><a href="#/">Back</a></p><p id="msg" class="err"></p>`);
  bindNav();
  const msg = document.getElementById("msg") as HTMLParagraphElement;
  const answer = async (id: string, decision: "approved" | "denied") => {
    const pa = state.pending.find((x) => x.id === id);
    if (!pa) return;
    try {
      if (decision === "approved") {
        const token = await createApproval({ card: pa.request.card, target: pa.request.target, action: pa.request.action, nonce: pa.request.nonce }, owner());
        await state.dir.answerApproval(reader(), id, { decision, token });
      } else {
        await state.dir.answerApproval(reader(), id, { decision });
      }
      await screenApprovals();
    } catch (e) {
      msg.textContent = err(e);
    }
  };
  document.querySelectorAll<HTMLButtonElement>("[data-approve]").forEach((b) => (b.onclick = () => answer(b.dataset["approve"]!, "approved")));
  document.querySelectorAll<HTMLButtonElement>("[data-deny]").forEach((b) => (b.onclick = () => answer(b.dataset["deny"]!, "denied")));
}

// ---------- approvals polling ----------

async function refreshPending(): Promise<void> {
  if (!state.root) return;
  try {
    const { pending } = await state.dir.pendingApprovals(reader());
    const had = state.pending.length;
    state.pending = pending;
    if (pending.length !== had && !location.hash.startsWith("#/approvals")) await route();
  } catch {
    /* directory offline */
  }
}

let polling = false;
async function pollApprovals(): Promise<void> {
  if (polling) return;
  polling = true;
  while (state.session.user) {
    await refreshPending();
    await new Promise((r) => setTimeout(r, 3000));
  }
  polling = false;
}

// ---------- router ----------

async function route(): Promise<void> {
  if (!state.session.user) return screenSignIn();
  if (!state.root) state.root = await loadOrCreateRootKey(state.session.user.id);
  const h = location.hash || "#/";
  const m = /^#\/(new|connect|agent|approvals)?\/?([^/]*)/.exec(h);
  const screen = m?.[1] ?? "";
  const arg = m?.[2] ?? "";
  try {
    if (screen === "new") return await screenNew();
    if (screen === "connect") return await screenConnect(arg);
    if (screen === "agent") return await screenAgent(arg);
    if (screen === "approvals") return await screenApprovals();
    return await screenHome();
  } catch (e) {
    render(`${nav()}<p class="err">${esc(err(e))}</p><p><a href="#/">Home</a></p>`);
    bindNav();
  }
}

async function main(): Promise<void> {
  const config = await server.config();
  const session = await server.session();
  state = { config, session, dir: directory(config.directoryUrl), pending: [] };
  window.addEventListener("hashchange", () => void route());
  await route();
  if (session.user) void pollApprovals();
}

void main();
