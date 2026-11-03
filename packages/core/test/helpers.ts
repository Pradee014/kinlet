import {
  fetchDirectoryClient,
  generateKeyPair,
  issueCard,
  MemoryNonceStore,
  MemorySpendLedger,
  signStatus,
  type Card,
  type CardStatus,
  type DirectoryClient,
  type KeyPair,
  type Permissions,
  type VerifierDeps,
} from "../src/index.js";

export const SHOP = "https://shop.example.com";
export const DIRECTORY = "https://directory.example.com";

export const defaultPermissions: Permissions = {
  services: [SHOP],
  actions: ["read", "purchase", "cancel"],
  limits: { currency: "USD", perAction: 50, perDay: 100 },
  approval: { above: 20, forActions: ["cancel"] },
};

export interface World {
  person: KeyPair;
  agent: KeyPair;
  directoryKey: KeyPair;
  card: Card;
  statuses: Map<string, CardStatus>;
  deps: VerifierDeps;
  nonces: MemoryNonceStore;
  ledger: MemorySpendLedger;
  now: () => Date;
  setNow: (d: Date) => void;
}

/** A fake directory that answers from a map, signed with a real key. */
export function fakeDirectory(directoryKey: KeyPair, statuses: Map<string, CardStatus>, nowFn: () => Date): DirectoryClient {
  return {
    async directoryDid() {
      return directoryKey.did;
    },
    async status(_url, serial) {
      return signStatus({ serial, status: statuses.get(serial) ?? "unknown" }, directoryKey, nowFn());
    },
  };
}

export async function makeWorld(overrides: { permissions?: Permissions; validUntil?: Date } = {}): Promise<World> {
  const person = await generateKeyPair();
  const agent = await generateKeyPair();
  const directoryKey = await generateKeyPair();
  let current = new Date("2026-11-03T12:00:00Z");
  const now = () => current;
  const issueInput: Parameters<typeof issueCard>[0] = {
    issuer: person,
    agentDid: agent.did,
    name: "Shopping agent",
    permissions: overrides.permissions ?? defaultPermissions,
    directory: DIRECTORY,
    validFrom: current,
  };
  if (overrides.validUntil) issueInput.validUntil = overrides.validUntil;
  const card = await issueCard(issueInput);
  const statuses = new Map<string, CardStatus>([[card.credentialStatus.serial, "valid"]]);
  const nonces = new MemoryNonceStore();
  const ledger = new MemorySpendLedger();
  const deps: VerifierDeps = {
    directory: fakeDirectory(directoryKey, statuses, now),
    nonces,
    ledger,
    now,
    serviceOrigin: SHOP,
  };
  return { person, agent, directoryKey, card, statuses, deps, nonces, ledger, now, setNow: (d) => (current = d) };
}

export { fetchDirectoryClient };
