# Kinlet

An ID card for your AI agent. You issue it, it says what the agent may do, services check it, and you can cancel it with one tap. Your own keys never leave your device; the AI model never sees a key at all.

Status: working prototype (v0.1). Everything in the first slice runs end to end: issue a card in the web app, let a Claude or any MCP-capable agent buy something at a demo shop, approve a larger purchase on your phone, revoke the card, and watch the agent be refused.

## Why

People hand AI agents their real passwords, cards and accounts. A hijacked agent then exposes everything. Kinlet gives the agent a card instead: scoped, capped, time-limited, instantly revocable, signed by you. Existing products in this space (Skyfire, Nekuda, Visa TAP, Coinbase agent wallets, Microsoft Entra Agent ID) sell to developers and enterprises and mostly stop at payments. Kinlet is the consumer product on top of the same open standards, for every kind of action, with the keys kept by the person. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full reasoning and prior art.

## What is in the box

| Package | What it is |
| --- | --- |
| `packages/core` | The open card format: keys (Ed25519, `did:key`), cards (W3C Verifiable Credentials, `eddsa-jcs-2022`), signed requests (RFC 9421 profile), approval tokens, revocation, event chains, and the verifier a service calls. Runs in Node and browsers. 48 tests, one per refusal case. |
| `packages/directory` | The directory service: registers cards, answers signed status queries, records revocations and hash-chained activity events, relays approval requests. SQLite. |
| `packages/mcp` | The plug-in any MCP-capable agent runs. Holds the agent key, signs requests, asks the owner for approval when the card says so, reports every attempt. Exposes three tools: `kinlet_card`, `kinlet_check`, `kinlet_act`. |
| `packages/demo-merchant` | A tiny shop. Its whole Kinlet integration is one `verifyIncomingRequest` call. |
| `apps/web` | The card office: passkey sign-in, create agent, one-time connect code, approvals, activity feed, cancel. The root key is a non-extractable WebCrypto key in the browser. |
| `docs/` | [Threat model](docs/THREAT_MODEL.md) and the [card format specification](docs/CARD_FORMAT.md). |

## Run the demo

Requirements: Node 22+, pnpm 10.

```sh
pnpm install
pnpm -r build
pnpm demo          # starts directory :7001, demo shop :7002, card office :7000
```

Open http://localhost:7000, create an account (a passkey; on a laptop without biometrics your browser will offer a PIN or a phone), tap "Create agent", pick the Shopping template, and copy the connect code. Then give it to an agent:

```sh
claude mcp add kinlet -e KINLET_AGENT=<paste the code> -- node packages/mcp/dist/cli.js
```

Ask the agent to buy a lamp at `http://localhost:7002` (it will call `kinlet_act`). Ask it to buy the chair: the app shows an approval request; approve or deny. Cancel the card in the app and ask again: refused.

To see the same flow without an AI in the loop:

```sh
pnpm test:browser   # drives the web app in Chromium with a virtual passkey and the runtime as the agent
```

## How it works, in one paragraph

You sign in with a passkey. The app creates your root key (non-extractable, in this browser) and, per agent, a separate agent key. The card is a small signed document: your DID, the agent's public key, the permissions, an expiry, a serial. The plug-in attaches the card to every request and signs the request with the agent key. A service verifies both signatures, enforces the card's limits, checks our directory for revocation (fail closed), and, when the card requires it, checks an approval token that only your root key can produce. Revoke flips the serial in the directory; every service sees it on the next request.

## Security notes for reviewers

- Start with [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md); every control there maps to code and a test.
- Nothing is lenient: a card with a missing limit, a wildcard service, an unknown field or a lifetime over 90 days is invalid.
- Replay protection: per-request nonces, 5-minute windows, content digests.
- Approval tokens are bound to card, target, canonical action and nonce, and must be signed by the card's issuer; the agent key cannot produce one (tested).
- The directory stores only serial, DIDs and validity; never names or permissions. All its answers are signed.
- Known gaps before any real money: root-key recovery, native apps with Secure Enclave keys, a multi-instance nonce store and ledger, an independent audit.

## Licence

MIT. The card format (`docs/CARD_FORMAT.md`) is intended to be implemented by anyone; please do.
