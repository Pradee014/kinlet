# Kinlet card format, version 1

This is the open part of Kinlet. Anyone may issue, hold, or verify a card; the format is not tied to
Kinlet's own app or directory. Keywords MUST, SHOULD, MAY are as in RFC 2119.

## 1. Identities and keys

- Persons and agents are identified by `did:key` DIDs over Ed25519 public keys
  (multicodec `ed25519-pub`, multibase base58btc, prefix `z6Mk`). No registry is needed to resolve
  them: the DID *is* the public key.
- A person holds a **root key**. It signs cards, approvals and revocations. It MUST be non-extractable
  on the person's device and MUST require a user gesture (passkey with user verification) to use.
- An agent holds an **agent key**. It signs requests. It is generated on the person's device and
  delivered to the agent runtime exactly once.

## 2. The card

A card is a W3C Verifiable Credential (data model 2.0) with a Data Integrity proof using the
`eddsa-jcs-2022` cryptosuite (JSON Canonicalization Scheme, RFC 8785, then Ed25519).

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://kinlet.dev/ns/card/v1"
  ],
  "type": ["VerifiableCredential", "KinletAgentCard"],
  "id": "urn:kinlet:card:7XK2Q9M4RZ8PWC3HV6TJ",
  "issuer": "did:key:z6MkpersonPublicKey",
  "validFrom": "2026-11-03T10:00:00Z",
  "validUntil": "2026-12-03T10:00:00Z",
  "credentialStatus": {
    "type": "KinletDirectoryStatus",
    "directory": "https://directory.kinlet.dev",
    "serial": "7XK2Q9M4RZ8PWC3HV6TJ"
  },
  "credentialSubject": {
    "id": "did:key:z6MkagentPublicKey",
    "name": "Shopping agent",
    "permissions": {
      "services": ["https://shop.example.com"],
      "actions": ["read", "purchase"],
      "limits": { "currency": "USD", "perAction": 50, "perDay": 100 },
      "approval": { "above": 20, "forActions": ["cancel"] }
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2026-11-03T10:00:00Z",
    "verificationMethod": "did:key:z6MkpersonPublicKey#z6MkpersonPublicKey",
    "proofPurpose": "assertionMethod",
    "proofValue": "z5...base58btc signature..."
  }
}
```

### 2.1 Field rules

| Field | Rule |
| --- | --- |
| `id` | `urn:kinlet:card:` + serial. Serial = 20 characters, Crockford base32, from 100 bits of CSPRNG. |
| `issuer` | The person's `did:key`. The proof MUST verify against this key. |
| `validFrom`, `validUntil` | RFC 3339 UTC. `validUntil` MUST be present and MUST be at most 90 days after `validFrom`. |
| `credentialStatus.directory` | HTTPS origin of the directory to query. Verifiers MUST query it (section 6). |
| `credentialSubject.id` | The agent's `did:key`. Requests MUST be signed by this key. |
| `permissions.services` | Non-empty list of HTTPS origins (scheme + host + optional port, no path). Wildcards are not allowed. |
| `permissions.actions` | Non-empty list from the action registry (section 3). |
| `permissions.limits` | Required if `actions` includes any monetary action. `perAction` and `perDay` are decimal numbers in `currency` (ISO 4217). |
| `permissions.approval.above` | Amount at or above which an approval token is required. MAY be 0 (always ask). |
| `permissions.approval.forActions` | Actions that always require approval, regardless of amount. |

A card with any unknown top-level field, a missing `validUntil`, or an empty `services` or `actions`
list is invalid. Verifiers MUST NOT be lenient: the point of the format is that limits are explicit.

### 2.2 Signing and verifying a card

1. Remove `proof`. Canonicalize the rest with JCS. Hash with SHA-256 → `docHash`.
2. Canonicalize the proof options (the `proof` object without `proofValue`) with JCS. Hash with SHA-256
   → `optionsHash`.
3. Sign `optionsHash || docHash` (64 bytes) with the issuer's Ed25519 key. `proofValue` = multibase
   base58btc of the 64-byte signature (`z` prefix).
4. Verify by recomputing both hashes and checking the signature against the key encoded in `issuer`.
   The `verificationMethod` MUST equal `issuer + "#" + <the did:key's method-specific id>`.

## 3. Action registry

| Action | Monetary | Meaning |
| --- | --- | --- |
| `read` | no | Fetch information from the service. |
| `purchase` | yes | Pay for an item or service. |
| `subscribe` | yes | Start a recurring charge. The amount is the per-period charge. |
| `cancel` | no | Cancel an order or subscription. |
| `book` | yes | Reserve something with a price (travel, appointment). |
| `message` | no | Send a message to a person or support channel. |
| `signin` | no | Authenticate to the service as the agent. |

Services MAY define further actions under a URI prefix they own (`https://shop.example.com/actions/returns`).

## 4. Signed requests

An agent presenting its card sends an HTTP request with these headers.

```
Kinlet-Card: <base64url(JSON card, UTF-8)>
Kinlet-Action: {"type":"purchase","amount":12.5,"currency":"USD","ref":"sku-123"}
Content-Digest: sha-256=:<base64 of SHA-256 of the body>:
Signature-Input: kinlet=("@method" "@target-uri" "content-digest" "kinlet-action");created=1762164000;expires=1762164300;nonce="<22+ chars base64url CSPRNG>";keyid="did:key:z6MkagentPublicKey";alg="ed25519";tag="kinlet-v1"
Signature: kinlet=:<base64 of the Ed25519 signature>:
Kinlet-Approval: <base64url(JSON approval token)>     (only when required)
```

This is a profile of HTTP Message Signatures (RFC 9421) and Content-Digest (RFC 9530):

- The covered components are exactly `@method`, `@target-uri`, `content-digest` and `kinlet-action`,
  in that order. Requests without a body MUST still carry `Content-Digest` over the empty string.
- `created` and `expires` are Unix seconds. `expires - created` MUST be at most 300.
- `nonce` MUST be unique per request. Services MUST remember nonces for at least the validity window.
- `keyid` MUST equal `credentialSubject.id` of the attached card.
- The signature base is built as RFC 9421 section 2.5 describes. The signature is Ed25519 over the
  UTF-8 bytes of the signature base.

`Kinlet-Action` is a JSON object with `type` (from the action registry), and for monetary actions
`amount` (decimal number) and `currency`. `ref` is a free-form service reference. Other keys are
ignored by verifiers but covered by the signature.

## 5. Approval tokens

When the card's `approval` rule applies to a request, the agent MUST obtain an approval token from the
person before sending it. The token binds the person's consent to that one request.

```json
{
  "type": "KinletApproval",
  "card": "7XK2Q9M4RZ8PWC3HV6TJ",
  "target": "https://shop.example.com/orders",
  "action": {"type":"purchase","amount":12.5,"currency":"USD","ref":"sku-123"},
  "nonce": "<the nonce the request will use>",
  "created": "2026-11-03T10:05:00Z",
  "expires": "2026-11-03T10:15:00Z",
  "proof": { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "...": "signed by the card's issuer" }
}
```

Rules: `expires - created` MUST be at most 10 minutes. The verifier MUST check that `card`, `target`
(= `@target-uri` without query string), JCS-canonical `action`, and `nonce` all match the request, and
that the proof verifies against the card's `issuer`. The agent key MUST NOT be able to produce this
token; that is the whole point.

Flow: the agent runtime picks the nonce, sends `{card, target, action, nonce}` to the person's app
(push notification), the app shows it in plain language, the person approves with a passkey gesture,
the root key signs, and the token comes back. The runtime then sends the request with that nonce.

## 6. Revocation and status

Every verifier MUST check status with the directory named in `credentialStatus.directory`.

### 6.1 Direct lookup (default)

`GET {directory}/v1/cards/{serial}/status` → `200`:

```json
{
  "type": "KinletStatus",
  "serial": "7XK2Q9M4RZ8PWC3HV6TJ",
  "status": "valid",            // "valid" | "revoked" | "unknown"
  "checkedAt": "2026-11-03T10:05:01Z",
  "directory": "did:key:z6MkdirectoryKey",
  "proof": { "...": "eddsa-jcs-2022 by the directory key" }
}
```

Verifiers MUST treat `revoked` and `unknown` as refusals. They MAY cache a `valid` answer for at most
60 seconds. If the directory is unreachable and no fresh cached answer exists, the verifier MUST refuse
(fail closed). The directory's key is published at `{directory}/.well-known/kinlet.json`.

### 6.2 Status list (optional, for high volume)

`GET {directory}/v1/status-lists/{id}` returns a Bitstring Status List credential signed by the
directory. Cards that opt in carry `statusListIndex` and `statusListCredential` in `credentialStatus`.
Lists MUST be re-issued at least every 60 seconds.

### 6.3 Revoking

`POST {directory}/v1/cards/{serial}/revoke` with a body signed by the card's issuer:

```json
{ "type": "KinletRevocation", "serial": "7XK2Q9M4RZ8PWC3HV6TJ", "revokedAt": "2026-11-03T11:00:00Z", "proof": { "..." : "by the issuer" } }
```

Revocation is permanent. A revoked serial is never reused.

## 7. Registering a card

`POST {directory}/v1/cards` with the full card as the body. The directory verifies the proof, stores
`serial`, `issuer`, `validUntil` and the subject DID, and returns `201` with the status document.
The directory stores nothing else from the card: not the name, not the permissions.

## 8. Activity events

The agent runtime SHOULD report each attempted action so the person can see it. Events are posted to
`POST {directory}/v1/cards/{serial}/events`, signed by the agent key, and hash-chained:

```json
{
  "type": "KinletEvent",
  "serial": "7XK2Q9M4RZ8PWC3HV6TJ",
  "seq": 42,
  "prev": "<SHA-256 of the previous event's canonical JSON, or 64 zeros>",
  "at": "2026-11-03T10:05:02Z",
  "target": "https://shop.example.com/orders",
  "action": {"type":"purchase","amount":12.5,"currency":"USD","ref":"sku-123"},
  "outcome": "ok",              // "ok" | "refused:<reason-code>" | "error"
  "proof": { "..." : "by the agent key" }
}
```

The directory accepts events only for serials it knows, only in sequence, and only with a valid chain.
A gap in `seq` is itself an alert to the person.

## 9. Reason codes

Verifiers return one of these, never free text, so apps can render them consistently:

`card_signature_invalid`, `card_expired`, `card_not_yet_valid`, `card_revoked`, `card_unknown`,
`directory_unreachable`, `request_signature_invalid`, `request_expired`, `request_replayed`,
`service_not_allowed`, `action_not_allowed`, `limit_exceeded`, `approval_required`,
`approval_invalid`, `card_malformed`.

## 10. Versioning

The context URL `https://kinlet.dev/ns/card/v1` and the `tag="kinlet-v1"` signature tag together name
this version. Verifiers MUST refuse cards and requests with versions they do not support.
