# Kinlet threat model

Status: living document. Every design decision in the code should trace back to a line here.
Last reviewed: 2026-11-03.

## 1. What Kinlet is, in one paragraph

Kinlet issues a signed "card" to a person's AI agent. The card says who the agent belongs to, what it
may do, within what limits, and until when. The agent presents the card and signs every request with
its own key. Services verify the card against the person's public identity and check Kinlet's directory
to see whether the card is still valid. The person can revoke the card with one tap. The person's own
keys never leave their device, and the AI model never sees any key.

## 2. Assets (what we protect, in priority order)

| # | Asset | Why it matters |
| --- | --- | --- |
| A1 | The person's root signing key | Whoever holds it can issue cards as the person. Compromise is total. |
| A2 | The person's ability to revoke | If revocation can be blocked or delayed, every other control is advisory. |
| A3 | An agent's private key | Lets the holder act as that agent, within the card's limits, until revoked. |
| A4 | Card integrity | A tampered card could widen limits or extend expiry. |
| A5 | The activity log | The person's only window into what the agent did; must be complete and tamper-evident. |
| A6 | The person's privacy | Services should learn "an authorized agent of identity X", not the person's name, email, or other cards. |
| A7 | Directory availability | If the directory is down, either everything stops (safe) or verification is skipped (unsafe). We choose safe. |

## 3. Trust boundaries

```
┌──────────────────────┐   issues card    ┌──────────────────────┐   signed request    ┌──────────────┐
│ Person's device      │ ───────────────▶ │ Agent runtime        │ ──────────────────▶ │ Service      │
│ (web app, passkey,   │                  │ (MCP plug-in holding │                     │ (merchant,   │
│  root key)           │ ◀─── approval ── │  the agent key; the  │ ◀── 402 / result ── │  API, site)  │
│                      │      request     │  AI model talks to   │                     │              │
└──────────┬───────────┘                  │  it, never to keys)  │                     └──────┬───────┘
           │ revoke / status              └──────────────────────┘                            │ status check
           ▼                                                                                  ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Kinlet directory (serial → status; public status list; revocation API)                          │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

Four boundaries, each crossed only by signed or authenticated messages:

1. Device ↔ agent runtime: the agent's private key crosses once, at creation, through a one-time code.
   The root key never crosses.
2. Agent runtime ↔ AI model: the model calls a tool ("act as my agent"); the tool signs. The model's
   context never contains a key. Anything in a model's context can leak through prompt injection.
3. Agent runtime ↔ service: card + signed request. The service trusts only signatures it verifies.
4. Anyone ↔ directory: reads are public and cacheable; writes (issue, revoke) require the person's
   signature.

## 4. Attackers

| Attacker | Capability | Goal |
| --- | --- | --- |
| T1 Prompt injector | Controls text the AI model reads (a web page, an email, a product listing). | Make the agent do something the person did not want. |
| T2 Agent-key thief | Has stolen the agent's private key and card (malware on the agent host, leaked config). | Act as the agent for as long as possible. |
| T3 Network attacker | Can read and replay traffic between agent and service. | Replay a signed request; modify a request in flight. |
| T4 Malicious service | Runs a service the agent talks to. | Over-charge, learn more about the person than it should, reuse the card elsewhere. |
| T5 Malicious AI model or runtime | The model or its host is hostile. | Exfiltrate keys, act outside limits, hide actions from the log. |
| T6 Lost or stolen device | Has the person's unlocked phone or laptop. | Issue new cards or revoke existing ones as the person. |
| T7 Kinlet insider or directory breach | Controls the directory database. | Un-revoke cards, forge status, read private data. |
| T8 Issuer impersonator | Runs a fake Kinlet. | Issue cards services will accept. |

## 5. Controls, mapped to attackers

| Control | Defeats | How |
| --- | --- | --- |
| C1 Root key is non-extractable and unlocked only by a passkey gesture | T5, T6 (partly), T7 | The root key is a non-extractable WebCrypto key; using it requires a fresh WebAuthn assertion (user verification = required). The server never sees it. |
| C2 Agent key is separate from the root key | T2, T5 | A stolen agent key gives only what the card allows, until revoked. It cannot mint cards. |
| C3 Card is signed by the root key and carries explicit limits | T2, T4 | Services verify the signature and enforce limits (spend cap, allowed services, allowed actions, expiry). A card with no limits is invalid by the format. |
| C4 Every request is signed by the agent key over method, target, body digest, time and nonce | T3, T4 | A request cannot be altered or replayed. Services reject requests older than 5 minutes or with a seen nonce. |
| C5 Card is bound to a service audience when presented | T4 | The signed request names the service; a service cannot replay the presentation elsewhere. |
| C6 Revocation checked on every request, fail closed | T2, T6, A7 | Services call the directory (or a cached status list no older than 60 s). Directory unreachable = refuse. |
| C7 Ask-me-first threshold, enforced by the service, not the agent | T1, T2, T5 | Actions above the card's threshold need an approval token signed by the root key, bound to the exact request. The agent cannot produce it. |
| C8 Tool, not secret: the model sees only a tool interface | T1, T5 | The MCP plug-in exposes "act" and "status" tools; no tool returns key material. |
| C9 Append-only activity log, hash-chained | T5, T7 | Each entry includes the hash of the previous one; the person's app can detect gaps. |
| C10 Issuer identity is the person's DID, not Kinlet | T7, T8 | Services verify against the person's public key. Kinlet's directory only answers "revoked or not" and is itself signed. A fake Kinlet cannot forge a person's signature. |
| C11 Signed directory responses | T7, T8 | Status answers are signed by the directory key, with a timestamp, so a man-in-the-middle cannot say "still valid". |
| C12 Minimal disclosure | T4 | The card carries the person's DID and the agent's key, not name, email, or other agents. |
| C13 Constant-time comparisons, no secrets in logs, no secrets in error messages | all | Enforced by code review and tests. |

## 6. Must-refuse cases (each one is a test)

A service using the Kinlet SDK must refuse, with a distinct reason code, when:

1. The card's signature does not verify against the issuer DID in the card.
2. The card is expired, or not yet valid.
3. The card's serial is revoked or unknown in the directory.
4. The directory cannot be reached and no fresh cached status exists.
5. The request signature does not verify against the agent key in the card.
6. The request is older than the allowed window or its nonce was seen before.
7. The request's target service is not in the card's allowed services.
8. The action is not in the card's allowed actions.
9. The amount exceeds the card's per-action or period limit.
10. The action requires approval and no valid approval token is present, or the token does not match
    the request hash, or it was signed by a key other than the card's issuer.
11. Any field is missing, has the wrong type, or the card version is unsupported.

The reason codes are stable strings so that the person's activity feed can show them in plain language.

## 7. What Kinlet does not protect against (and says so)

- A person who approves a bad action. Kinlet shows exactly what will happen; it cannot judge wisdom.
- An agent that does something harmful that needs no card at all (reading a public page, giving advice).
- A compromised operating system on the person's device. Passkeys and non-extractable keys raise the
  bar; they do not beat a rooted device.
- A service that ignores the card's limits. Kinlet can only refuse to vouch; the service must enforce.
  This is why the format is open and the SDK makes enforcement a one-line call.

## 8. Residual risks and open decisions

| Risk | Current answer | Revisit when |
| --- | --- | --- |
| Loss of the device = loss of the root key | V1: a recovery key shown once at setup, to be stored offline. V2: second-device recovery. | Before private beta. |
| Non-extractable browser keys are bound to one browser profile | Acceptable for v1 web app; native apps use the Secure Enclave. | Launch phase. |
| Directory is a single operator | Format allows any directory; the card names which one to check. Federation later. | After the format is published. |
| Clock skew between agent and service | 5-minute window; signed timestamps. | If services report false refusals. |

## 9. Prior art (and what Kinlet adds)

- imToken Sigil: passkey-signed approval of agent actions inside one crypto wallet. Kinlet adds a
  portable identity usable with any service, and non-payment actions.
- Skyfire KYA: agent identity tokens issued and held by Skyfire. Kinlet keeps keys with the person and
  makes the person's DID, not the issuer, the root of trust.
- Sigilum, KYA-OS (DIF): DID/VC-based agent identity for developers. Kinlet is the consumer product
  on top of the same standards.
- Visa TAP, Google AP2: HTTP message signatures and signed mandates for payments. Kinlet's request
  signing and approval tokens are designed to be carried inside those where a service speaks them.

## 10. Standards used

- Keys and signatures: Ed25519 (WebCrypto, Node, browsers).
- Identity: did:key for persons and agents (self-certifying; no registry needed to verify).
- Card: W3C Verifiable Credential data model, signed with a Data Integrity proof
  (eddsa-jcs-2022: JSON Canonicalization Scheme + Ed25519).
- Request signing: profile of HTTP Message Signatures (RFC 9421) with Content-Digest (RFC 9530).
- Person authentication to the web app: WebAuthn passkeys with user verification required.
- Revocation: direct status lookup plus a Bitstring Status List for cached verification.
