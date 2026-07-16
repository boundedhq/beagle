// Human wording for a leak alert (non-core: the core engine decides WHEN to
// alert and emits the facts; this decides how they read). Copy rules:
// - Lead with "Beagle": macOS shows osascript notifications under Script
//   Editor's name and icon (an Apple limitation of `display notification`),
//   so the TEXT itself must say who is talking.
// - Say what leaked and where in plain words ("AWS access key sent to
//   Anthropic"), not detector tags ("aws-access-key-id → anthropic/model").
// - Be honest that the data already left the machine, and give exactly one
//   next step: open the dashboard.
import type { AlertEvent } from "../core/alert/engine";
import type { AlertMessage } from "./notifier";

// Providers users actually route to. Unknown providers fall back to the raw
// name — never wrong, just less polished.
const PROVIDER_NAMES: Record<string, string> = {
  anthropic: "Anthropic",
  openai: "OpenAI",
  google: "Google",
  mistral: "Mistral",
  openrouter: "OpenRouter",
};

// Plain-English names for the common detector types (bare noun phrase, no
// article). Fallback de-kebabs the tag: "foo-api-token" → "foo api token".
const SECRET_NAMES: Record<string, string> = {
  "aws-access-key-id": "AWS access key",
  "aws-secret-access-key": "AWS secret key",
  "github-pat": "GitHub personal access token",
  "github-oauth": "GitHub OAuth token",
  "github-app-token": "GitHub app token",
  "stripe-access-token": "Stripe API key",
  "slack-bot-token": "Slack bot token",
  "slack-user-token": "Slack user token",
  "gcp-api-key": "Google Cloud API key",
  "openai-api-key": "OpenAI API key",
  "anthropic-api-key": "Anthropic API key",
  "private-key": "private key",
  "jwt": "JWT token",
  "generic-api-key": "API key",
};

export function providerName(p: string): string {
  return PROVIDER_NAMES[p] ?? p;
}

export function secretName(t: string): string {
  return SECRET_NAMES[t] ?? t.replace(/-/g, " ");
}

/** The OS-notification / terminal wording for one structured alert. */
export function buildAlertMessage(a: AlertEvent): AlertMessage {
  const provider = providerName(a.provider);
  const secret = secretName(a.secretType);
  const title = `Beagle — ${secret} sent to ${provider}${a.seenBefore ? " again" : ""}`;
  const sender = a.agent ?? "an agent";
  const via = a.model ? ` (model ${a.model})` : "";
  const ownKey = a.destinationOwnKey
    ? ` Note: it is ${provider}'s own API key, pasted into the message body.`
    : "";
  const body =
    `Sent by ${sender}${via} — the data already left your machine; ` +
    `Beagle alerts, it can't block.${ownKey} Review: beagle ui`;
  return { title, body };
}
