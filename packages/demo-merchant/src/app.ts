/**
 * Demo merchant. Two public endpoints (catalog, health) and two agent endpoints (orders, cancel).
 * The whole Kinlet integration is the `verifyIncomingRequest` call in `requireCard`.
 */
import { Hono, type Context } from "hono";
import {
  fetchDirectoryClient,
  MemoryNonceStore,
  MemorySpendLedger,
  verifyIncomingRequest,
  type DirectoryClient,
  type NonceStore,
  type SpendLedger,
  type VerifyResult,
} from "@kinlet/core";

export interface MerchantOptions {
  /** This merchant's public origin; must match what cards list under `services`. */
  origin: string;
  directory?: DirectoryClient;
  nonces?: NonceStore;
  ledger?: SpendLedger;
  now?: () => Date;
}

export interface Item {
  sku: string;
  name: string;
  price: number;
  currency: "USD";
}

export const CATALOG: Item[] = [
  { sku: "lamp-01", name: "Desk lamp", price: 12.5, currency: "USD" },
  { sku: "mug-02", name: "Ceramic mug", price: 8, currency: "USD" },
  { sku: "chair-03", name: "Office chair", price: 45, currency: "USD" },
  { sku: "desk-04", name: "Standing desk", price: 240, currency: "USD" },
];

export interface Order {
  id: string;
  sku: string;
  amount: number;
  currency: string;
  serial: string;
  agent: string;
  at: string;
  status: "placed" | "cancelled";
}

export function createMerchantApp(opts: MerchantOptions): { app: Hono; orders: Map<string, Order> } {
  const now = opts.now ?? (() => new Date());
  const ledger = opts.ledger ?? new MemorySpendLedger();
  const deps = {
    directory: opts.directory ?? fetchDirectoryClient(),
    nonces: opts.nonces ?? new MemoryNonceStore(),
    ledger,
    now,
    serviceOrigin: opts.origin,
  };
  const orders = new Map<string, Order>();
  const app = new Hono();

  app.get("/healthz", (c) => c.json({ ok: true }));
  app.get("/catalog", (c) => c.json({ items: CATALOG }));

  /**
   * Verifies the incoming request with Kinlet. On failure returns the HTTP response to send;
   * on success returns the verification result (card, action, amount).
   */
  const requireCard = async (c: Context): Promise<{ ok: true; v: Extract<VerifyResult, { ok: true }> } | { ok: false; res: Response }> => {
    const headers: Record<string, string> = {};
    c.req.raw.headers.forEach((v, k) => (headers[k] = v));
    const body = await c.req.raw.text();
    // Reconstruct the public URL the agent signed: the origin we are known as + the request path.
    const incoming = new URL(c.req.url);
    const url = opts.origin + incoming.pathname + incoming.search;
    const v = await verifyIncomingRequest(deps, { method: c.req.method, url, headers, body });
    if (!v.ok) {
      const status = v.reason === "approval_required" ? 402 : v.reason === "directory_unreachable" ? 503 : 403;
      return { ok: false, res: c.json({ error: v.reason, detail: v.detail }, status) };
    }
    return { ok: true, v };
  };

  app.post("/orders", async (c) => {
    const r = await requireCard(c);
    if (!r.ok) return r.res;
    const { v } = r;
    if (v.action.type !== "purchase") return c.json({ error: "action_not_allowed", detail: "orders need a purchase action" }, 403);
    const item = CATALOG.find((i) => i.sku === v.action.ref);
    if (!item) return c.json({ error: "unknown_item" }, 404);
    // The signed action must say what the merchant will charge. No silent price changes.
    if (v.action.amount !== item.price || v.action.currency !== item.currency) return c.json({ error: "price_mismatch", expected: item.price }, 409);
    const id = "ord_" + Math.random().toString(36).slice(2, 10);
    const order: Order = { id, sku: item.sku, amount: item.price, currency: item.currency, serial: v.serial, agent: v.card.credentialSubject.id, at: now().toISOString(), status: "placed" };
    orders.set(id, order);
    await ledger.record(v.serial, item.currency, v.amountMinor ?? 0, now());
    return c.json({ order }, 201);
  });

  app.post("/orders/:id/cancel", async (c) => {
    const r = await requireCard(c);
    if (!r.ok) return r.res;
    const { v } = r;
    if (v.action.type !== "cancel") return c.json({ error: "action_not_allowed" }, 403);
    const order = orders.get(c.req.param("id"));
    if (!order) return c.json({ error: "unknown_order" }, 404);
    // Only the card that placed the order may cancel it.
    if (order.serial !== v.serial) return c.json({ error: "forbidden" }, 403);
    order.status = "cancelled";
    return c.json({ order });
  });

  app.notFound((c) => c.json({ error: "not_found" }, 404));
  return { app, orders };
}
