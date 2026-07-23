// A closed-loop proof that Beagle's normal daemon path works. The generated
// canary can only travel proxy -> 127.0.0.1 mock; the resulting call and leak
// use the ordinary store/viewer path, carrying a reserved [demo] identity.
import { randomBytes, randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { listenReady } from "../core/net/listen";
import { DEMO_AGENT } from "../core/call";
import { Store } from "../core/store/store";
import { BEAGLE_VERSION } from "../core/version";
import { controlRequest } from "../daemon/control";
import { cmdUi, ensureDaemon, staleDaemonRemedy, type DaemonInfo } from "./commands";

const CANARY_ALPHABET = "BCDFGHJKLMNPQRSTVWYZbcdfghjklmnpqrstvwxyz0123456789+/";
const DEMO_STEP_TIMEOUT_MS = 3_000;
const DEMO_PERSIST_TIMEOUT_MS = 5_000;
const DEMO_MODEL = "claude-sonnet-4-demo";
const DEMO_FILE = "/tmp/beagle-canary/.env";
const DEMO_TOOL_ID = "toolu_beagle_demo";
const DEMO_PROMPT =
  "Can you find the AWS secret access key configured for the project in /tmp/beagle-canary?";

export interface DemoMock {
  port: number;
  close(): Promise<void>;
}

export interface DemoResult {
  sessionId: string;
}

interface DemoDependencies {
  generateCanary: () => string;
  startMock: () => Promise<DemoMock>;
  ensureDaemon: (stateDir: string) => Promise<DaemonInfo | null>;
  exchange: (daemon: DaemonInfo, mock: DemoMock, canary: string, runId: string) => Promise<void>;
  waitForLeak: (stateDir: string, runId: string) => Promise<DemoResult>;
  openUi: (stateDir: string, sessionId: string) => Promise<string>;
  out: (text: string) => void;
  err: (text: string) => void;
}

/** Generate a detector-valid but never-issued AWS-secret-shaped value. A
 *  shuffled alphabet makes all 40 characters distinct, guaranteeing the
 *  production rule's entropy gate; excluding vowels prevents stopwords. */
export function generateDemoCanary(
  bytes: Uint8Array = randomBytes(CANARY_ALPHABET.length - 1),
): string {
  if (bytes.length < CANARY_ALPHABET.length - 1) {
    throw new Error(`demo canary generation needs ${CANARY_ALPHABET.length - 1} random bytes`);
  }
  const chars = [...CANARY_ALPHABET];
  for (let i = chars.length - 1; i > 0; i--) {
    const j = bytes[chars.length - 1 - i]! % (i + 1);
    [chars[i], chars[j]] = [chars[j]!, chars[i]!];
  }
  return chars.slice(0, 40).join("");
}

const TOOL_CALL_SSE = [
  'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_beagle_demo_read","type":"message","role":"assistant","model":"claude-sonnet-4-demo","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":42,"output_tokens":0}}}',
  'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
  'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"I’ll check the project’s environment configuration."}}',
  'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}',
  `event: content_block_start\ndata: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"${DEMO_TOOL_ID}","name":"Read","input":{"file_path":"${DEMO_FILE}"}}}`,
  'event: content_block_stop\ndata: {"type":"content_block_stop","index":1}',
  'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":24}}',
  'event: message_stop\ndata: {"type":"message_stop"}',
  "",
].join("\n\n");

const FINAL_ANSWER_SSE = [
  'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_beagle_demo_answer","type":"message","role":"assistant","model":"claude-sonnet-4-demo","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":89,"output_tokens":0}}}',
  'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
  'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"I found an AWS secret access key in the project’s .env file. Confirm that it belongs to the intended staging account "}}',
  'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"and rotate it if it may have been exposed. "}}',
  'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Avoid pasting credentials into chats or logs."}}',
  'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}',
  'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":48}}',
  'event: message_stop\ndata: {"type":"message_stop"}',
  "",
].join("\n\n");

export async function startDemoMock(): Promise<DemoMock> {
  let requestCount = 0;
  const server = createServer((request, response) => {
    request.resume();
    const body = requestCount++ === 0 ? TOOL_CALL_SSE : FINAL_ANSWER_SSE;
    response.writeHead(200, {
      "content-type": "text/event-stream",
      "content-length": String(Buffer.byteLength(body)),
      "request-id": "req_beagle_demo",
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
  return { port: address.port, close: () => closeServer(server) };
}

/** Register the loopback upstream, then send an Anthropic-shaped Read tool
 * turn and its result through the daemon's real proxy. There is intentionally
 * no provider URL or environment fallback anywhere in this function. */
export async function runDemoExchange(
  daemon: DaemonInfo,
  mock: DemoMock,
  canary: string,
  runId: string,
): Promise<void> {
  const upstream = `http://127.0.0.1:${mock.port}`;
  const registration = await controlRequest(daemon.socketPath, {
    cmd: "register-run",
    args: { id: runId, agent: DEMO_AGENT, provider: "loopback-demo", upstream },
  });
  if (!registration.ok) throw new Error(`could not register demo run: ${registration.error}`);

  const userMessage = {
    role: "user",
    content: DEMO_PROMPT,
  };
  const toolUse = {
    role: "assistant",
    content: [
      { type: "text", text: "I’ll check the project’s environment configuration." },
      {
        type: "tool_use",
        id: DEMO_TOOL_ID,
        name: "Read",
        input: { file_path: DEMO_FILE },
      },
    ],
  };
  const send = async (messages: unknown[]): Promise<void> => {
    const response = await fetch(
      `http://127.0.0.1:${daemon.proxyPort}/run/${runId}/v1/messages`,
      {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(DEMO_STEP_TIMEOUT_MS),
      headers: {
        "content-type": "application/json",
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: DEMO_MODEL,
        max_tokens: 128,
        stream: true,
        system: "You are a coding assistant helping inspect a local project.",
        tools: [{
          name: "Read",
          description: "Read a file from the local filesystem.",
          input_schema: {
            type: "object",
            properties: { file_path: { type: "string" } },
            required: ["file_path"],
          },
        }],
        messages,
      }),
      },
    );
    await response.arrayBuffer();
    if (!response.ok) throw new Error(`loopback mock returned HTTP ${response.status}`);
  };

  await send([userMessage]);
  await send([
    userMessage,
    toolUse,
    {
      role: "user",
      content: [{
        type: "tool_result",
        tool_use_id: DEMO_TOOL_ID,
        content: `AWS_SECRET_ACCESS_KEY=${canary}`,
      }],
    },
  ]);
}

export async function waitForDemoLeak(stateDir: string, runId: string): Promise<DemoResult> {
  const deadline = Date.now() + DEMO_PERSIST_TIMEOUT_MS;
  while (Date.now() < deadline) {
    let store: Store | null = null;
    try {
      store = Store.openReadOnly(stateDir);
      const row = store.queryAll<{ session_id: string }>(
        `SELECT e.session_id FROM exchanges e
         WHERE e.run_id = ? AND e.agent = ?
           AND EXISTS(SELECT 1 FROM leak_occurrences lo WHERE lo.exchange_id = e.id)
         ORDER BY e.ts_request DESC LIMIT 1`,
        [runId, DEMO_AGENT],
      )[0];
      if (row) return { sessionId: row.session_id };
    } catch {
      // The daemon may still be creating the store; poll until the bounded
      // deadline, then report the missing end-to-end result.
    } finally {
      store?.close();
    }
    await Bun.sleep(50);
  }
  throw new Error("demo alert was not persisted by the daemon");
}

function productionDependencies(): DemoDependencies {
  return {
    generateCanary: generateDemoCanary,
    startMock: startDemoMock,
    ensureDaemon,
    exchange: runDemoExchange,
    waitForLeak: waitForDemoLeak,
    openUi: cmdUi,
    out: (text) => process.stdout.write(text),
    err: (text) => process.stderr.write(text),
  };
}

export async function cmdDemo(
  stateDir: string,
  overrides: Partial<DemoDependencies> = {},
): Promise<number> {
  const deps = { ...productionDependencies(), ...overrides };
  let mock: DemoMock | null = null;
  try {
    const canary = deps.generateCanary();
    // Fail closed: the daemon is not even contacted until the loopback-only
    // mock has successfully bound. A bind failure has no route to fall back to.
    mock = await deps.startMock();
    const daemon = await deps.ensureDaemon(stateDir);
    if (!daemon) throw new Error("could not start the beagle daemon");
    // Unlike an ordinary capture, the drill promises this build's exact UI,
    // copy, count exclusion, and cleanup behavior. An older live daemon owns
    // all four surfaces, so proceeding would produce a misleading demo.
    if (daemon.runningVersion !== BEAGLE_VERSION) {
      const running = daemon.runningVersion ? `v${daemon.runningVersion}` : "an unknown version";
      throw new Error(
        `the running daemon is ${running}; restart it before the drill: ` +
        staleDaemonRemedy(stateDir, daemon.pid),
      );
    }
    const runId = `demo-${randomUUID()}`;
    await deps.exchange(daemon, mock, canary, runId);
    const result = await deps.waitForLeak(stateDir, runId);
    const dashboard = await deps.openUi(stateDir, result.sessionId);
    if (!dashboard.startsWith("dashboard:")) throw new Error(dashboard);
    deps.out(
      "beagle demo complete\n\n" +
      "  ✓ Generated a synthetic AWS-secret-shaped canary\n" +
      "  ✓ Simulated an agent reading it from a local .env file\n" +
      "  ✓ Captured and detected it through Beagle's normal daemon path\n" +
      "  ✓ Sent it only to an in-process mock on 127.0.0.1\n" +
      "  ✓ Saved the result locally with a [demo] badge\n\n" +
      `${dashboard}\n\n` +
      "That was a drill — nothing left this machine.\n" +
      'Run "beagle run <agent>" to watch a real session. ' +
      '"beagle demo --clean" removes demo records.\n',
    );
    return 0;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    deps.err(
      `beagle demo failed safely: ${reason}\n` +
      "No request was sent to a model provider. " +
      'Run "beagle demo --clean" to remove any partial drill record.\n',
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
