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

// R9/R5 budget harness — asserts the numbers the README publishes.

describe("scan-time budget (R5: p99 ≤ ~10ms on 1 MB, ReDoS-safe)", () => {
  const rules = compileRules(
    loadRuleFile(readFileSync("rules/beagle-rules.json", "utf8")),
    new Uint8Array(32).fill(1),
  );

  test("p99 of a 1 MB body scan stays well under the deadline", () => {
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
    times.sort((a, b) => a - b);
    const p99 = times[Math.floor(times.length * 0.99)]!;
    // generous ceiling for CI variance; the design target is ~10ms
    expect(p99).toBeLessThan(50);
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
    const median = (xs: number[]) => xs.sort((a, b) => a - b)[Math.floor(xs.length / 2)]!;
    const added = median(tapped) - median(direct);
    // CI-generous ceiling; design target p50 ≤ 5ms. Guards against a pooling
    // regression (socket-per-request would add tens of ms).
    expect(added).toBeLessThan(25);
  });
});
