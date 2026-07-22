// Worker-side entry for the scanner (design §6.3). Receives an init message
// (rule content + HMAC key), then scan requests with transferable body bytes.
import { compileRules, scan, type CompiledRules, type ScanCtx } from "../core/scanner/engine";
import { loadRuleFile, type RuleSpec } from "../core/scanner/rules";

interface InitMsg {
  kind: "init";
  rulesJson: string;
  rulesPin?: string;
  extraRules?: RuleSpec[];
  hmacKey: Uint8Array;
}
interface ScanMsg {
  kind: "scan";
  id: number;
  bytes: ArrayBuffer;
  ctx: ScanCtx;
}

let compiled: CompiledRules | null = null;

self.onmessage = (event: MessageEvent<InitMsg | ScanMsg>) => {
  const msg = event.data;
  if (msg.kind === "init") {
    const specs = loadRuleFile(msg.rulesJson, msg.rulesPin);
    compiled = compileRules([...specs, ...(msg.extraRules ?? [])], msg.hmacKey);
    return;
  }
  if (!compiled) throw new Error("scan before init");
  const result = scan(new Uint8Array(msg.bytes), msg.ctx, compiled);
  postMessage({ kind: "result", id: msg.id, ...result });
};
