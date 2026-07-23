// Human wording for a leak alert (non-core: the core engine decides WHEN to
// alert and emits the facts; this decides how they read). Copy rules:
// - Lead with "Beagle": macOS shows osascript notifications under Script
//   Editor's name and icon (an Apple limitation of `display notification`),
//   so the TEXT itself must say who is talking.
// - Say what leaked and where in plain words (title "secret sent to
//   Anthropic", subtitle "AWS access key"), not detector tags.
// - Be honest that it has already been sent, and give exactly one next step,
//   framed as a command to run — a new user doesn't know what "beagle ui" is.
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

/** The OS-notification / terminal wording for one structured alert.
 *
 *  macOS truncates the banner TITLE hard (~35 chars visible), so the three
 *  lines each carry one job and each fits its own budget:
 *    title     Beagle — secret sent to Anthropic        (short, never clipped)
 *    subtitle  AWS access key                           (the specifics)
 *    body      Already sent by your claude-code agent.
 *              Run "beagle ui" for details.             (the next step, own line)
 *  The body leads with "Already sent" — the honest, can't-undo part — then
 *  attributes the agent; no dangling "it" (the secret is named on the line
 *  above). No lecture ("Beagle alerts, it can't block") — that's product
 *  philosophy, not something to repeat on every alert. The model name lives
 *  in the dashboard, not the banner. */
export function buildAlertMessage(a: AlertEvent): AlertMessage {
  const provider = providerName(a.provider);
  const title = `Beagle — secret sent to ${provider}${a.seenBefore ? " again" : ""}`;
  const subtitle = secretName(a.secretType);
  const sender = a.agent ? `your ${a.agent} agent` : "an agent";
  const ownKey = a.destinationOwnKey
    ? ` It is ${provider}'s own API key, pasted into the message body.`
    : "";
  // The next step gets its own line — a newline the notifier renders on macOS
  // (AppleScript \n) and Linux (notify-send), and collapses in the one-line
  // terminal backstop.
  const body = `Already sent by ${sender}.${ownKey}\nRun "beagle ui" for details.`;
  return { title, subtitle, body };
}

/** Drill wording stays explicit on every alert surface and deliberately
 * ignores seenBefore: each demo run is meant to prove notification delivery. */
export function buildDemoAlertMessage(a: AlertEvent): AlertMessage {
  return {
    title: "Beagle [demo] — canary detected",
    subtitle: secretName(a.secretType),
    body: "Drill only — sent to a loopback mock.\nOpen the dashboard to inspect the captured demo.",
  };
}
