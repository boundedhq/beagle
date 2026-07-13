import { join } from "node:path";
import { opencodeAuthMode } from "../install/detect";

// The four v1 CLI agents (R2) and their redirect knobs. claude/codex honor a
// base-URL env var; opencode is config-driven via a Beagle-owned config file;
// pi loads a Beagle-owned extension via its per-run `-e` flag.
export interface ConfigRedirect {
  /** Env var that overrides the config-file location (e.g. OPENCODE_CONFIG). */
  configEnv: string;
  /** Where to set the proxy base URL inside the config (dotted path as array). */
  baseUrlPath: string[];
  /** Candidate real-config paths to merge from, so the user's other settings
   *  survive. Given the user's home dir. */
  realConfigCandidates: (home: string) => string[];
}

export interface ExtensionRedirect {
  /** CLI flag that loads an extension file for one run (pi: `-e`). */
  flag: string;
  /** Provider id whose baseUrl the generated extension re-points. */
  baseUrlProvider: string;
}

export interface AgentSpec {
  command: string;
  provider: string;
  upstream: string;
  authLocation: string;
  baseUrlEnv?: string;
  config?: ConfigRedirect;
  extension?: ExtensionRedirect;
  extraHeaders?: Array<[string, string]>;
  /** Auth-dependent upstream override (e.g. opencode's ChatGPT OAuth backend).
   *  Returns undefined to use `upstream`. */
  resolveUpstream?: (home: string) => string | undefined;
  /** Whether `--telemetry` (Mode B, agent self-report capture) is supported and
   *  which vendor OTel wiring to use. Both agents export to Beagle's loopback
   *  receiver; they differ in how it's turned on — `claude` via env vars + a
   *  PostToolUse hook for tool output, `codex` via `-c` config flags (its export
   *  carries tool output natively). */
  telemetry?: "claude" | "codex";
  /** Wire redirect via prepended CLI args instead of a base-URL env var, for an
   *  agent that ignores the env var (codex). Given the per-run proxy URL,
   *  returns the argv to inject before the user's own args. */
  wireArgs?: (baseUrl: string) => string[];
}

/** Codex ignores OPENAI_BASE_URL and refuses to override its built-in `openai`
 *  provider, so wire capture needs a CUSTOM provider pointed at the proxy
 *  (verified live: codex 0.144.x POSTs to <base_url>/responses). env_key reads
 *  the user's own OPENAI_API_KEY (Beagle scrubs it before storing); the run URL
 *  carries no /v1 — codex appends /responses and the proxy prepends the
 *  upstream's /v1. */
export function buildCodexWireArgs(baseUrl: string): string[] {
  return [
    "-c", 'model_provider="beagle"',
    "-c", 'model_providers.beagle.name="beagle"',
    "-c", `model_providers.beagle.base_url="${baseUrl}"`,
    "-c", 'model_providers.beagle.env_key="OPENAI_API_KEY"',
    "-c", 'model_providers.beagle.wire_api="responses"',
  ];
}

export const AGENTS: Record<string, AgentSpec> = {
  claude: {
    command: "claude",
    provider: "anthropic",
    upstream: "https://api.anthropic.com",
    authLocation: "x-api-key",
    baseUrlEnv: "ANTHROPIC_BASE_URL",
    telemetry: "claude",
  },
  codex: {
    command: "codex",
    provider: "openai",
    // codex appends /responses to the custom provider's base_url — the /v1
    // lives in the upstream, which the proxy prepends.
    upstream: "https://api.openai.com/v1",
    authLocation: "authorization",
    // NOT baseUrlEnv: codex ignores OPENAI_BASE_URL (verified live). Wire mode
    // (API-key login) redirects via a custom provider; a ChatGPT login can't
    // be wire-redirected at all, so --telemetry captures it via OTel instead.
    wireArgs: buildCodexWireArgs,
    telemetry: "codex",
  },
  opencode: {
    command: "opencode",
    provider: "openai",
    // opencode's openai baseURL default includes /v1 (it appends /responses);
    // a ChatGPT-plan OAuth login speaks to the Codex backend instead —
    // resolveUpstream picks per login (verified live both ways).
    upstream: "https://api.openai.com/v1",
    resolveUpstream: (home) =>
      opencodeAuthMode(home, process.env.XDG_DATA_HOME) === "oauth"
        ? "https://chatgpt.com/backend-api/codex"
        : undefined,
    authLocation: "authorization",
    // Config-driven (verified in the PRD): OPENCODE_CONFIG points at a config
    // file whose provider.openai.options.baseURL Beagle redirects.
    config: {
      configEnv: "OPENCODE_CONFIG",
      baseUrlPath: ["provider", "openai", "options", "baseURL"],
      realConfigCandidates: (home) => [
        join(home, ".config", "opencode", "opencode.json"),
        join(home, ".config", "opencode", "opencode.jsonc"),
      ],
    },
  },
  pi: {
    command: "pi",
    provider: "openai",
    // pi's builtin openai provider uses the Responses API — it appends
    // /responses to its base (verified in @earendil-works/pi-ai: the openai
    // provider is openAIResponsesApi with baseUrl "https://api.openai.com/v1").
    upstream: "https://api.openai.com/v1",
    authLocation: "authorization",
    // Verified against pi's docs (badlogic/pi-mono, coding-agent):
    // `pi -e <file.ts>` loads an extension for one run, and
    // `pi.registerProvider("openai", { baseUrl })` re-points the builtin
    // provider while keeping all its models. No config or auth files are
    // touched — the least invasive redirect of the four agents.
    extension: { flag: "-e", baseUrlProvider: "openai" },
  },
};

// The base URL an agent should be pointed at for a given run.
export function runBaseUrl(proxyPort: number, runId: string): string {
  return `http://127.0.0.1:${proxyPort}/run/${runId}`;
}

export function buildRunEnv(agent: string, proxyPort: number, runId: string): Record<string, string> {
  const spec = AGENTS[agent];
  if (!spec?.baseUrlEnv) return {};
  return { [spec.baseUrlEnv]: runBaseUrl(proxyPort, runId) };
}
