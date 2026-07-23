// A closed-loop proof that Beagle's real proxy, scanner, and notifier work.
// The demo deliberately has no Store/Daemon/Viewer dependency: its generated
// canary travels only proxy -> 127.0.0.1 mock, and the finding is never saved.
import { randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { ScanHost, type ScanResult } from "../adapters/scan-host";
import { listenReady } from "../core/net/listen";
import { ProxyServer, type RunLookup } from "../core/proxy/server";
import { parseUpstream } from "../core/proxy/http1";
import type { ResolvedRun } from "../core/proxy/registry";
import type { Finding } from "../core/scanner/engine";
import { secretName } from "../notifier/alert-copy";
import { Notifier, type AlertMessage } from "../notifier/notifier";
import embeddedRulesRaw from "../../rules/beagle-rules.json" with { type: "text" };
import embeddedRulesPin from "../../rules/beagle-rules.sha256" with { type: "text" };

const embeddedRules = embeddedRulesRaw as unknown as string;
const CANARY_ALPHABET = "BCDFGHJKLMNPQRSTVWYZ23456789";
const DEMO_RUN_ID = "local-demo";
const DEMO_STEP_TIMEOUT_MS = 2_000;

export interface DemoMock {
  port: number;
  close(): Promise<void>;
}

interface DemoDependencies {
  generateCanary: () => string;
  startMock: () => Promise<DemoMock>;
  exchange: (mock: DemoMock, canary: string) => Promise<Finding>;
  notify: (message: AlertMessage) => void;
  out: (text: string) => void;
  err: (text: string) => void;
}

/** Generate a detector-valid but unusable AWS-shaped value. The alphabet has
 *  no vowels or X, so scanner stopwords such as EXAMPLE and XXXXXX cannot
 *  occur by chance. */
export function generateDemoCanary(bytes: Uint8Array = randomBytes(16)): string {
  if (bytes.length < 16) throw new Error("demo canary generation needs 16 random bytes");
  let suffix = "";
  for (const byte of bytes.subarray(0, 16)) {
    suffix += CANARY_ALPHABET[byte % CANARY_ALPHABET.length];
  }
  return `AKIA${suffix}`;
}

export function demoAlertMessage(finding: Finding): AlertMessage {
  return {
    title: "Beagle demo — canary detected",
    subtitle: secretName(finding.secretType),
    body: "Drill only — sent to a loopback mock.\nNothing left this machine, and nothing was retained.",
  };
}

export async function startDemoMock(): Promise<DemoMock> {
  const server = createServer((request, response) => {
    request.resume();
    const body = '{"ok":true}';
    response.writeHead(200, {
      "content-type": "application/json",
      "content-length": String(Buffer.byteLength(body)),
      connection: "close",
    });
    response.end(body);
  });

  await listenReady(server, () => server.listen(0, "127.0.0.1"));
  const address = server.address() as AddressInfo;
  if (address.address !== "127.0.0.1") {
    await closeServer(server);
    throw new Error("demo mock did not bind to IPv4 loopback");
  }
  return {
    port: address.port,
    close: () => closeServer(server),
  };
}

export async function runDemoExchange(mock: DemoMock, canary: string): Promise<Finding> {
  const upstream = `http://127.0.0.1:${mock.port}`;
  const run: ResolvedRun = {
    id: DEMO_RUN_ID,
    agent: "beagle-demo",
    provider: "loopback-demo",
    upstream,
    parsedUpstream: parseUpstream(upstream),
  };
  const registry: RunLookup = {
    resolve: (runId) => runId === DEMO_RUN_ID ? run : null,
  };
  const scanner = new ScanHost({
    rulesJson: embeddedRules,
    rulesPin: embeddedRulesPin.trim(),
    hmacKey: randomBytes(32),
    deadlineMs: 500,
  });

  let settleScan: ((result: ScanResult) => void) | undefined;
  const scanned = new Promise<ScanResult>((resolve) => { settleScan = resolve; });
  const proxy = new ProxyServer({
    registry,
    captureBufferCap: 1 << 20,
    scan: async (bytes, ctx) => {
      const result = await scanner.scan(bytes, { authValue: ctx.authValue });
      settleScan?.(result);
      settleScan = undefined;
      return result;
    },
    onCall: () => {},
  });

  try {
    await proxy.listen(0);
    const response = await fetch(`http://127.0.0.1:${proxy.port}/run/${DEMO_RUN_ID}/v1/demo`, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(DEMO_STEP_TIMEOUT_MS),
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "beagle-demo",
        messages: [{ role: "user", content: `AWS_ACCESS_KEY_ID=${canary}` }],
      }),
    });
    await response.arrayBuffer();
    if (!response.ok) throw new Error(`loopback mock returned HTTP ${response.status}`);

    const result = await withTimeout(scanned, DEMO_STEP_TIMEOUT_MS, "demo scan did not complete");
    if (result.state !== "ok") throw new Error("demo scan was incomplete");
    const finding = result.findings.find(
      (item) => item.tier === "structured" && item.secretType === "aws-access-key-id",
    );
    if (!finding) throw new Error("production rules did not detect the generated canary");
    return finding;
  } finally {
    proxy.close();
    scanner.close();
  }
}

function productionDependencies(): DemoDependencies {
  const notifier = new Notifier();
  return {
    generateCanary: generateDemoCanary,
    startMock: startDemoMock,
    exchange: runDemoExchange,
    notify: (message) => notifier.notify(message),
    out: (text) => process.stdout.write(text),
    err: (text) => process.stderr.write(text),
  };
}

export async function cmdDemo(overrides: Partial<DemoDependencies> = {}): Promise<number> {
  const deps = { ...productionDependencies(), ...overrides };
  let mock: DemoMock | null = null;
  try {
    const canary = deps.generateCanary();
    // Fail closed: no exchange exists until the loopback-only mock has bound.
    mock = await deps.startMock();
    const finding = await deps.exchange(mock, canary);
    deps.notify(demoAlertMessage(finding));
    deps.out(
      "beagle demo complete\n\n" +
      "  ✓ Generated a fake AWS-shaped canary\n" +
      "  ✓ Detected it through Beagle's real proxy and scanner\n" +
      "  ✓ Sent it only to a mock on 127.0.0.1\n\n" +
      "This was a drill. Nothing left this machine, and nothing was retained.\n" +
      'Run "beagle detect" when you are ready to capture an agent.\n',
    );
    return 0;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    deps.err(
      `beagle demo failed safely: ${reason}\n` +
      "No request was sent to a model provider, and nothing was retained.\n",
    );
    return 1;
  } finally {
    if (mock) await mock.close().catch(() => {});
  }
}

function closeServer(server: Server): Promise<void> {
  if (!server.listening) return Promise.resolve();
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); },
    );
  });
}
