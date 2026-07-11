// Dedup + alert engine (design §6.5). Detection marks everything; alerting
// dedups: upsert on (fingerprint, destination, session) — a fresh row fires
// the loud alert, a conflict silently updates the event. Only the
// structured tier is loud (R5/R6).
import type { Finding } from "../scanner/engine";
import type { Store } from "../store/store";

export interface ExchangeMeta {
  id: string;
  sessionId: string;
  agent?: string;
  provider: string;
  model?: string;
}

export interface AlertEvent {
  eventId: string;
  exchangeId: string;
  title: string;
  body: string;
  seenBefore: boolean;
}

export type AlertSink = (alert: AlertEvent) => void;

export class AlertEngine {
  constructor(
    private store: Store,
    private sink: AlertSink,
  ) {}

  process(ex: ExchangeMeta, findings: Finding[]): void {
    // Dedup keys on the destination PROVIDER (R6) — a mid-session model
    // switch is the same destination and must not re-alert. The model only
    // enriches the human-facing copy.
    const displayDestination = ex.model ? `${ex.provider}/${ex.model}` : ex.provider;
    for (const f of findings) {
      const seenBefore = this.store.fingerprintKnown(f.fingerprint);
      const { fresh, eventId } = this.store.upsertLeakEvent({
        fingerprint: f.fingerprint,
        sessionId: ex.sessionId,
        detector: f.detector,
        secretType: f.secretType,
        severity: f.severity,
        confidenceTier: f.tier,
        destination: ex.provider,
        exchangeId: ex.id,
        ts: Date.now(),
      });
      if (fresh && f.tier === "structured") {
        this.sink({
          eventId,
          exchangeId: ex.id,
          seenBefore,
          ...alertCopy(f, ex, displayDestination, seenBefore),
        });
      }
    }
  }
}

function alertCopy(
  f: Finding,
  ex: ExchangeMeta,
  destination: string,
  seenBefore: boolean,
): { title: string; body: string } {
  const title = `${seenBefore ? "Secret sent again" : "Secret detected"}: ${f.secretType}`;
  const ownKey = f.destinationOwnKey
    ? " (this destination's own API key appeared in the message body)" : "";
  const body =
    `${f.secretType} sent to ${destination} by ${ex.agent ?? "unknown agent"}${ownKey}. ` +
    `The data has already been sent — Beagle observes, it does not block. ` +
    // 12 chars: same-millisecond ULIDs share their first 8, so an 8-char
    // prefix can be ambiguous exactly when a burst of exchanges lands.
    `Details: beagle show ${ex.id.slice(0, 12)}`;
  return { title, body };
}
