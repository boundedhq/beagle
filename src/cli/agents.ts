// The four v1 CLI agents (R2) and their redirect knobs. claude/codex honor a
// base-URL env var; opencode/pi are config-driven — their wrapper support
// arrives with the Beagle-owned-config machinery (watch/shim, PR 9).
export interface AgentSpec {
  command: string;
  provider: string;
  upstream: string;
  authLocation: string;
  baseUrlEnv?: string;
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
    // config-driven: provider.<id>.options.baseURL via a Beagle-owned config (PR 9)
  },
  pi: {
    command: "pi",
    provider: "openai",
    upstream: "https://api.openai.com",
    authLocation: "authorization",
    // config-driven (PR 9)
  },
};

export function buildRunEnv(agent: string, proxyPort: number, runId: string): Record<string, string> {
  const spec = AGENTS[agent];
  if (!spec?.baseUrlEnv) return {};
  return { [spec.baseUrlEnv]: `http://127.0.0.1:${proxyPort}/run/${runId}` };
}
