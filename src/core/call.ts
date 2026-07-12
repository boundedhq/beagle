// Canonical Call — the source-pluggable seam (design §5). Both capture
// sources (wire proxy, OTLP receiver) converge on this shape; scanner,
// session resolver, store, and UI stay source-agnostic.

export type CaptureSource = "wire" | "otel";

export interface Message {
  role: string;
  content: string;
}

export interface Call {
  id: string;
  runId: string;
  source: CaptureSource;
  agent?: string;
  provider: string;
  model?: string;
  endpoint: string;
  request: {
    headers?: Array<[string, string]>;
    bodyBytes: Uint8Array;
    messages?: Message[];
  };
  response: {
    status?: number;
    headers?: Array<[string, string]>;
    bodyBytes?: Uint8Array;
    // Raw response stream exactly as received (event framing, pre-reassembly)
    // — kept for streamed responses only, drives the R7 Layer-2 fidelity view.
    sseRaw?: Uint8Array;
    text?: string;
  };
  meta: {
    tsRequest: number;
    tsResponse?: number;
    tokensIn?: number;
    tokensOut?: number;
  };
}
