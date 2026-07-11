// Canonical Exchange — the source-pluggable seam (design §5). Both capture
// sources (wire proxy, OTLP receiver) converge on this shape; scanner,
// session resolver, store, and UI stay source-agnostic.

export type CaptureSource = "wire" | "otel";

export interface Message {
  role: string;
  content: string;
}

export interface Exchange {
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
    text?: string;
  };
  meta: {
    tsRequest: number;
    tsResponse?: number;
    tokensIn?: number;
    tokensOut?: number;
  };
}
