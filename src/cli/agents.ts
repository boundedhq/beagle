import { join } from "node:path";

// The four v1 CLI agents (R2) and their redirect knobs. claude/codex honor a
// base-URL env var; opencode is config-driven via a Beagle-owned config file.
export interface ConfigRedirect {
  /** Env var that overrides the config-file location (e.g. OPENCODE_CONFIG). */
  configEnv: string;
  /** Where to set the proxy base URL inside the config (dotted path as array). */
  baseUrlPath: string[];
  /** Candidate real-config paths to merge from, so the user's other settings
   *  survive. Given the user's home dir. */
  realConfigCandidates: (home: string) => string[];
}

export interface AgentSpec {
  command: string;
  provider: string;
  upstream: string;
  authLocation: string;
  baseUrlEnv?: string;
  config?: ConfigRedirect;
  extraHeaders?: Array<[string, string]>;
}

export const AGENTS: Record<string, AgentSpec> = {
  claude: {
    command: "claude",
    provider: "anthropic",
    upstream: "https://api.anthropic.com",
    authLocation: "x-api-key",
    baseUrlEnv: "ANTHROPIC_BASE_URL",
  },
  codex: {
    command: "codex",
    provider: "openai",
    upstream: "https://api.openai.com",
    authLocation: "authorization",
    baseUrlEnv: "OPENAI_BASE_URL",
  },
  opencode: {
    command: "opencode",
    provider: "openai",
    upstream: "https://api.openai.com",
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
    upstream: "https://api.openai.com",
    authLocation: "authorization",
    // pi is config-driven, but its exact config-override knob is not yet
    // confirmed by the Phase-0 spike; left without a `config` descriptor so
    // `beagle run pi` refuses honestly rather than guessing the env var.
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
