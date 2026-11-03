#!/usr/bin/env node
/**
 *   KINLET_MERCHANT_PORT   default 7002
 *   KINLET_MERCHANT_URL    public origin as cards will name it, default http://localhost:<port>
 */
import { serve } from "@hono/node-server";
import { createMerchantApp } from "./app.js";

const port = Number(process.env["KINLET_MERCHANT_PORT"] ?? "7002");
const origin = process.env["KINLET_MERCHANT_URL"] ?? `http://localhost:${port}`;
const { app } = createMerchantApp({ origin });
serve({ fetch: app.fetch, port }, () => console.log(`demo merchant listening on ${origin}`));
