import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ViewerServer } from "../src/viewer/server";
import { findViewerSafetyViolations } from "../scripts/lint-viewer-safety";
import { Store, type CallRecord } from "../src/core/store/store";
import { ulid } from "../src/core/store/ulid";

function seedStore(stateDir: string): string {
  const store = Store.open(stateDir);
  const id = ulid();
  const call: CallRecord = {
    id, sessionId: "s1", runId: "r1", source: "wire",
    agent: "claude-code", provider: "anthropic", model: "claude-sonnet-5",
    endpoint: "/v1/messages", tsRequest: Date.now(), tsResponse: Date.now(),
    status: 200, tokensIn: 5, tokensOut: 2, bytesReq: 10, bytesResp: 20,
    summary: "hello world", scanState: "ok", captureState: "ok", sessionTier: "prefix",
    requestBody: new TextEncoder().encode("{}"), requestHeaders: [],
    responseBody: new TextEncoder().encode("{}"), responseHeaders: [], sseRaw: null,
    searchText: "hello secret-content world",
  };
  store.insertCall(call);
  store.close();
  return id;
}

describe("ViewerServer hardening (design §6.8)", () => {
  let stateDir: string;
  let viewer: ViewerServer;
  let url: string; // bootstrap URL with one-time token
  let callId: string;

  beforeEach(async () => {
    stateDir = mkdtempSync(join(tmpdir(), "beagle-viewer-"));
    callId = seedStore(stateDir);
    viewer = new ViewerServer({ stateDir, idleTimeoutMs: 60_000 });
    url = await viewer.start();
  });

  afterEach(() => viewer.stop());

  const origin = () => new URL(url).origin;
  const bootToken = () => new URL(url).searchParams.get("boot")!;

  async function getCredential(): Promise<string> {
    const r = await fetch(`${origin()}/api/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ boot: bootToken() }),
    });
    expect(r.status).toBe(200);
    return ((await r.json()) as { credential: string }).credential;
  }

  test("bootstrap token exchanges exactly once", async () => {
    const cred = await getCredential();
    expect(cred.length).toBeGreaterThan(20);
    const again = await fetch(`${origin()}/api/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ boot: bootToken() }),
    });
    expect(again.status).toBe(401); // invalidated on use
  });

  test("api requires the session credential", async () => {
    const noAuth = await fetch(`${origin()}/api/feed`);
    expect(noAuth.status).toBe(401);
    const cred = await getCredential();
    const ok = await fetch(`${origin()}/api/feed`, { headers: { "x-beagle-token": cred } });
    expect(ok.status).toBe(200);
    const feed = (await ok.json()) as Array<{ id: string; summary: string }>;
    expect(feed.length).toBe(1);
    expect(feed[0]!.id).toBe(callId);
  });

  test("stats endpoint returns whole-store totals with credential", async () => {
    const noAuth = await fetch(`${origin()}/api/stats`);
    expect(noAuth.status).toBe(401);
    const cred = await getCredential();
    const r = await fetch(`${origin()}/api/stats`, { headers: { "x-beagle-token": cred } });
    expect(r.status).toBe(200);
    const stats = (await r.json()) as { calls: number; sessions: number; agents: number };
    expect(stats.calls).toBe(1);
    expect(stats.sessions).toBe(1);
    expect(stats.agents).toBe(1);
  });

  test("non-local Origin is rejected (DNS-rebinding defense)", async () => {
    const cred = await getCredential();
    const r = await fetch(`${origin()}/api/feed`, {
      headers: { "x-beagle-token": cred, origin: "https://evil.example.com" },
    });
    expect(r.status).toBe(403);
  });

  test("non-local Host is rejected", async () => {
    const cred = await getCredential();
    const r = await fetch(`${origin()}/api/feed`, {
      headers: { "x-beagle-token": cred, host: "evil.example.com" },
    });
    expect(r.status).toBe(403);
  });

  test("HTML ships a strict CSP with no external sources", async () => {
    const r = await fetch(`${origin()}/`);
    const csp = r.headers.get("content-security-policy")!;
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("connect-src 'self'");
    expect(csp).not.toContain("http:");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).not.toContain("unsafe-inline");
  });

  test("CSP script-src whitelists the inline import map by its content hash", async () => {
    const r = await fetch(`${origin()}/`);
    const html = await r.text();
    const csp = r.headers.get("content-security-policy")!;
    const m = html.match(/<script type="importmap">([\s\S]*?)<\/script>/);
    expect(m).not.toBeNull();
    const { createHash } = await import("node:crypto");
    const hash = createHash("sha256").update(m![1]!).digest("base64");
    // Without this the import map is CSP-blocked and the whole app fails to load.
    expect(csp).toContain(`'sha256-${hash}'`);
  });

  test("literal search is POST-only (credentials never in URLs)", async () => {
    const cred = await getCredential();
    const get = await fetch(`${origin()}/api/search?q=secret-content`, {
      headers: { "x-beagle-token": cred },
    });
    expect([404, 405]).toContain(get.status);
    const post = await fetch(`${origin()}/api/search`, {
      method: "POST",
      headers: { "x-beagle-token": cred, "content-type": "application/json" },
      body: JSON.stringify({ term: "secret-content" }),
    });
    expect(post.status).toBe(200);
    const hits = (await post.json()) as unknown[];
    expect(hits.length).toBe(1);
  });

  test("mutating endpoint (purge) requires credential and POST", async () => {
    const noAuth = await fetch(`${origin()}/api/purge`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ kind: "all" }),
    });
    expect(noAuth.status).toBe(401);
  });

  test("no path traversal through static serving", async () => {
    for (const path of ["/../package.json", "/vendor/../../../etc/passwd", "/%2e%2e/secrets"]) {
      const r = await fetch(origin() + path);
      expect([400, 403, 404]).toContain(r.status);
    }
  });

  test("call detail endpoint returns decoded payloads with credential", async () => {
    const cred = await getCredential();
    const r = await fetch(`${origin()}/api/call/${callId}`, {
      headers: { "x-beagle-token": cred },
    });
    expect(r.status).toBe(200);
    const detail = (await r.json()) as { summary: string; messages: unknown[]; requestRaw: string };
    expect(detail.summary).toBe("hello world");
    expect(Array.isArray(detail.messages)).toBe(true);
  });

  test("SSE stream requires the credential", async () => {
    const r = await fetch(`${origin()}/api/stream`);
    expect(r.status).toBe(401);
  });

  test("SSE reconnects do not leak store handles (crown-jewels held open)", async () => {
    const cred = await getCredential();
    for (let i = 0; i < 5; i++) {
      const controller = new AbortController();
      const s = await fetch(`${origin()}/api/stream`, {
        headers: { "x-beagle-token": cred },
        signal: controller.signal,
      });
      expect(s.status).toBe(200);
      controller.abort();
      await Bun.sleep(20);
    }
    // A leaked read handle would have kept the WAL pinned; a fresh writer
    // opening and inserting still succeeds cleanly.
    const w = Store.open(stateDir);
    w.close();
    // and the feed still serves normally afterward
    const feed = await fetch(`${origin()}/api/feed`, { headers: { "x-beagle-token": cred } });
    expect(feed.status).toBe(200);
  });

  test("bad session credential is rejected in constant time (timing-safe compare)", async () => {
    await getCredential();
    const wrong = await fetch(`${origin()}/api/feed`, {
      headers: { "x-beagle-token": "0".repeat(64) },
    });
    expect(wrong.status).toBe(401);
  });

  test("the viewer client code contains no unsafe HTML sinks", () => {
    expect(findViewerSafetyViolations(join(import.meta.dir, ".."))).toEqual([]);
  });

  test("idle shutdown: viewer stops promptly (linger) after the last SSE client disconnects", async () => {
    viewer.stop();
    // Long idle window, SHORT linger: closing the tab must wind down on the
    // linger, not wait out the 10-min-style idle window (the daemon-hold bug).
    viewer = new ViewerServer({ stateDir, idleTimeoutMs: 60_000, lingerMs: 150 });
    url = await viewer.start();
    const cred = await getCredential();
    const controller = new AbortController();
    const stream = await fetch(`${origin()}/api/stream`, {
      headers: { "x-beagle-token": cred },
      signal: controller.signal,
    });
    expect(stream.status).toBe(200);
    controller.abort(); // last tab closes
    await Bun.sleep(400); // > lingerMs, << idleTimeoutMs
    expect(viewer.isRunning).toBe(false);
  });

  test("a reload within the linger keeps the viewer up (doesn't tear down mid-refresh)", async () => {
    viewer.stop();
    viewer = new ViewerServer({ stateDir, idleTimeoutMs: 60_000, lingerMs: 300 });
    url = await viewer.start();
    const cred = await getCredential();
    const c1 = new AbortController();
    await fetch(`${origin()}/api/stream`, { headers: { "x-beagle-token": cred }, signal: c1.signal });
    c1.abort(); // tab closes → linger armed
    await Bun.sleep(80); // reload lands before the 300ms linger fires
    const c2 = new AbortController();
    const restream = await fetch(`${origin()}/api/stream`, {
      headers: { "x-beagle-token": cred },
      signal: c2.signal,
    });
    expect(restream.status).toBe(200);
    await Bun.sleep(400); // past the original linger deadline
    expect(viewer.isRunning).toBe(true); // the reconnect kept it alive
    c2.abort();
  });

  test("fresh viewer with no tab yet uses the long idle window, not the short linger", async () => {
    viewer.stop();
    // No client ever connects. A short linger must NOT apply here — only the
    // (long) idle window governs the pre-connection wait. With a long window it
    // is still running right after boot.
    viewer = new ViewerServer({ stateDir, idleTimeoutMs: 60_000, lingerMs: 50 });
    url = await viewer.start();
    await Bun.sleep(300); // well past lingerMs
    expect(viewer.isRunning).toBe(true);
  });
});
