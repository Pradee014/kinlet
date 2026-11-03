/** Plain-language rendering. No crypto words reach the screen. */

export interface ActionLike {
  type: string;
  amount?: number;
  currency?: string;
  ref?: string;
}

export function money(amount: number | undefined, currency: string | undefined): string {
  if (amount === undefined) return "";
  try {
    return new Intl.NumberFormat(undefined, { style: "currency", currency: currency ?? "USD" }).format(amount);
  } catch {
    return `${amount} ${currency ?? ""}`;
  }
}

export function host(target: string): string {
  try {
    return new URL(target).host;
  } catch {
    return target;
  }
}

export function describeAction(a: ActionLike, target: string): string {
  const at = host(target);
  const what = a.ref ? ` ${a.ref}` : "";
  switch (a.type) {
    case "purchase":
      return `Buy${what} for ${money(a.amount, a.currency)} at ${at}`;
    case "subscribe":
      return `Start a subscription${what} at ${money(a.amount, a.currency)} per period at ${at}`;
    case "book":
      return `Book${what} for ${money(a.amount, a.currency)} at ${at}`;
    case "cancel":
      return `Cancel${what} at ${at}`;
    case "message":
      return `Send a message${what ? " to" + what : ""} at ${at}`;
    case "signin":
      return `Sign in at ${at}`;
    case "read":
      return `Read from ${at}`;
    default:
      return `${a.type}${what} at ${at}`;
  }
}

const REASONS: Record<string, string> = {
  card_signature_invalid: "the card did not check out",
  card_expired: "the card has expired",
  card_not_yet_valid: "the card is not valid yet",
  card_revoked: "you cancelled this card",
  card_unknown: "the card is not registered",
  directory_unreachable: "Kinlet could not be reached, so the service refused",
  request_signature_invalid: "the request was not properly signed",
  request_expired: "the request was too old",
  request_replayed: "the request was a repeat",
  service_not_allowed: "this service is not on the card",
  action_not_allowed: "this action is not on the card",
  limit_exceeded: "it was over the spending limit",
  approval_required: "it needed your approval",
  approval_invalid: "the approval did not match",
  approval_denied: "you said no",
  approval_timeout: "you did not answer in time",
  card_malformed: "the card was malformed",
  bad_url: "the address was invalid",
  network_error: "the service could not be reached",
};

export function describeOutcome(outcome: string): { text: string; good: boolean } {
  if (outcome === "ok") return { text: "Done", good: true };
  if (outcome === "error") return { text: "Failed", good: false };
  const code = outcome.replace(/^refused:/, "");
  return { text: `Refused: ${REASONS[code] ?? code}`, good: false };
}

export function when(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}
