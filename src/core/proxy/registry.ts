// Run registry (design §6.1): /run/<uuid> → upstream + auth location.
// Write-through to the runs table so a daemon restart under always-on shims
// never leaves a live agent sending to an unresolvable run id.
import type { Store } from "../store/store";
import { parseUpstream, type Upstream, type HeaderList } from "./http1";

export interface RunRegistration {
  id: string;
  agent: string;
  provider: string;
  upstream: string; // base URL, e.g. https://api.anthropic.com
  authLocation?: string; // header name carrying the provider credential
  extraHeaders?: HeaderList; // headers to re-add if the agent drops them (R2)
}

export interface ResolvedRun extends RunRegistration {
  parsedUpstream: Upstream;
}

export class RunRegistry {
  private cache = new Map<string, ResolvedRun>();

  constructor(private store: Store) {
    for (const r of store.listRuns()) this.cacheRun(r);
  }

  register(reg: RunRegistration): void {
    this.store.insertRun({
      id: reg.id,
      agent: reg.agent,
      provider: reg.provider,
      upstream: reg.upstream,
      authLocation: reg.authLocation ?? null,
      extraHeaders: reg.extraHeaders ?? null,
      createdTs: Date.now(),
    });
    this.cacheRun(reg);
  }

  resolve(runId: string): ResolvedRun | null {
    return this.cache.get(runId) ?? null;
  }

  private cacheRun(reg: RunRegistration): void {
    this.cache.set(reg.id, { ...reg, parsedUpstream: parseUpstream(reg.upstream) });
  }
}
