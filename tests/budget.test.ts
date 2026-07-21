import { afterAll, describe, expect, test } from "bun:test";
import { createServer, connect, type Server } from "node:net";
import { readFileSync } from "node:fs";
import { compileRules, scan } from "../src/core/scanner/engine";
import { loadRuleFile } from "../src/core/scanner/rules";
import { ProxyServer } from "../src/core/proxy/server";
import { RunRegistry } from "../src/core/proxy/registry";
import { Store } from "../src/core/store/store";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// R9/R5 budget harness — the gates behind the README's performance table. The
// published numbers (R5 p99, R9 p50) are design targets; what each gate proves
// is a MEDIAN under a CI-generous ceiling — see the comments inside for why no
// wall-clock gate on a shared runner can prove a tail.

// Both budgets below assert a median. These are wall-clock samples taken on a
// shared CI runner, so the tail is that runner's scheduling noise (a GC pause,
// CPU steal) rather than anything about Beagle; only the middle of the
// distribution is about the code under test. Sorts in place — callers here
// don't reuse the sample order.
const median = (xs: number[]) => xs.sort((a, b) => a - b)[Math.floor(xs.length / 2)]!;

describe("scan-time budget (median 1 MB scan under CI ceilings; R5's p99 ≤ ~10ms is the design target, not what this proves)", () => {
  const rules = compileRules(
    loadRuleFile(readFileSync("rules/beagle-rules.json", "utf8")),
    new Uint8Array(32).fill(1),
  );

  test("median 1 MB body scan stays well under the deadline", () => {
    let body = "";
    const chunk = 'const config = { url: "https://api.example.com", note: "regular text here" };\n';
    while (body.length < 1 << 20) body += chunk;
    const bytes = new TextEncoder().encode(body);
    const times: number[] = [];
    for (let i = 0; i < 30; i++) {
      const t = performance.now();
      scan(bytes, {}, rules);
      times.push(performance.now() - t);
    }
    // Deliberately NOT a tail index: every sample scans the same bytes, so the
    // spread across them is runner noise, and `times[Math.floor(n * 0.99)]` is
    // the max for any n ≤ 100 (floor(100 * 0.99) === 99, the last index) — that
    // read cost an unrelated PR a green build. Raising the sample count doesn't
    // make it a p99; n ≥ 200 is needed to drop even one sample.
    // The p99 ≤ ~10ms design target (PRD R5) is not what this gate proves, and
    // no wall-clock gate on a shared runner could. What bounds a pathological
    // input is the scan worker's 500ms deadline — a fail-safe that marks the
    // exchange incomplete, 50x this target, covered by tests/scan-host.test.ts.
    // generous ceiling for CI variance; the design target is ~10ms
    expect(median(times)).toBeLessThan(50);
  });

  // The body above contains no JSON escapes, so it takes the single-pass fast
  // path and would not notice the second view at all. Tool-call traffic is the
  // shape that forces BOTH passes, and it is the common case in practice, so
  // the budget needs a sample of it.
  //
  // The chunk carries secret-ish KEYWORDS on purpose. The prescan is the lever
  // that keeps scan time flat, so a keyword-free body measures almost nothing:
  // only 3 of 30 rules survive it, and the second pass re-runs just those. With
  // keywords it is 5 of 30 — still not "every rule", which no realistic body
  // reaches. (The ratio to the plain-body gate is machine-specific: measured
  // between 2.2x and 3.9x on different hosts, so no number is quoted here.)
  //
  // Note what this body did BEFORE the change that added this gate: masking used
  // to leave `\"` alone, so a body whose only escapes were quotes took the
  // single-pass fast path. Blanking them is what moves ordinary tool-call
  // traffic onto two passes. The cost below is that decision's, not a standing
  // property of two-view scanning.
  //
  // What this catches is a blow-up: masking going superlinear, or a third view
  // being added. It is far too loose to catch a modest regression, exactly as
  // with the plain-body gate above, and nothing here proves the R5 p99 target.
  // The ceiling keeps roughly the same headroom over the local median that the
  // gate above does, so a slow shared runner doesn't turn it into a flake.
  test("median 1 MB escape-dense body scan stays well under the deadline", () => {
    let body = "";
    const chunk = String.raw`{"tool_calls":[{"function":{"name":"write_file","arguments":"{\"path\":\".env\",\"content\":\"AWS_SECRET_ACCESS_KEY=changeme\\napi_key: none\\npassword: none\\n\"}"}}]},` + "\n";
    while (body.length < 1 << 20) body += chunk;
    const bytes = new TextEncoder().encode(body);
    const times: number[] = [];
    for (let i = 0; i < 30; i++) {
      const t = performance.now();
      scan(bytes, {}, rules);
      times.push(performance.now() - t);
    }
    expect(median(times)).toBeLessThan(150);
  });
});

describe("proxy added-latency budget (R9: p50 ≤ ~5ms over direct)", () => {
  let upstream: Server;
  let upstreamPort: number;
  let proxy: ProxyServer;
  let store: Store;

  function startUpstream(): Promise<void> {
    return new Promise((resolve) => {
      upstream = createServer((sock) => {
        let buf = "";
        sock.on("data", (d) => {
          buf += d.toString("latin1");
          const i = buf.indexOf("\r\n\r\n");
          if (i === -1) return;
          const m = buf.match(/content-length:\s*(\d+)/i);
          if (buf.length < i + 4 + (m ? Number(m[1]) : 0)) return;
          buf = "";
          const body = '{"ok":true}';
          sock.write(`HTTP/1.1 200 OK\r\ncontent-length: ${body.length}\r\n\r\n${body}`);
        });
        sock.on("error", () => {});
      });
      upstream.listen(0, "127.0.0.1", () => {
        upstreamPort = (upstream.address() as { port: number }).port;
        resolve();
      });
    });
  }

  function oneRequest(port: number, path: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const body = '{"messages":[{"role":"user","content":"hi"}]}';
      const raw = `POST ${path} HTTP/1.1\r\nHost: h\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
      const start = performance.now();
      const sock = connect(port, "127.0.0.1", () => sock.write(raw));
      let got = "";
      sock.on("data", (d) => {
        got += d.toString();
        if (got.includes("ok")) {
          resolve(performance.now() - start);
          sock.end();
        }
      });
      sock.on("error", reject);
    });
  }

  afterAll(() => {
    proxy?.close();
    upstream?.close();
    store?.close();
  });

  test("median added latency over a warm direct baseline is small", async () => {
    await startUpstream();
    store = Store.open(mkdtempSync(join(tmpdir(), "beagle-budget-")));
    const registry = new RunRegistry(store);
    registry.register({
      id: "run-b", agent: "claude-code", provider: "anthropic",
      upstream: `http://127.0.0.1:${upstreamPort}`, authLocation: "x-api-key",
    });
    proxy = new ProxyServer({
      registry,
      scan: () => Promise.resolve(),
      onCall: () => {},
      captureBufferCap: 1 << 20,
    });
    await proxy.listen(0);

    const warm = 20, n = 60;
    // warm both paths (TCP/keep-alive)
    for (let i = 0; i < warm; i++) {
      await oneRequest(upstreamPort, "/v1/messages");
      await oneRequest(proxy.port, "/run/run-b/v1/messages");
    }
    const direct: number[] = [];
    const tapped: number[] = [];
    for (let i = 0; i < n; i++) {
      direct.push(await oneRequest(upstreamPort, "/v1/messages"));
      tapped.push(await oneRequest(proxy.port, "/run/run-b/v1/messages"));
    }
    const added = median(tapped) - median(direct);
    // CI-generous ceiling; design target p50 ≤ 5ms. Guards against a pooling
    // regression (socket-per-request would add tens of ms).
    expect(added).toBeLessThan(25);
  });
});
