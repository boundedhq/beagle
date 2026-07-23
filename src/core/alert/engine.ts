// Dedup + alert engine (design §6.5). Detection marks everything; alerting
// dedups: upsert on (fingerprint, destination, session) — a fresh row fires
// the loud alert, a conflict silently updates the event. Only the
// structured tier is loud (R5/R6), except rules explicitly marked as
// non-alerting because they recognize identifiers rather than credentials.
import type { Finding } from "../scanner/engine";
import type { Store } from "../store/store";

export interface CallMeta {
  id: string;
  sessionId: string;
  agent?: string;
  provider: string;
  model?: string;
}

// Structured alert facts. Core decides WHEN to alert and what happened; the
// human wording lives outside the security path (notifier/alert-copy.ts).
export interface AlertEvent {
  eventId: string;
  callId: string;
  seenBefore: boolean;
  secretType: string;
  agent?: string;
  provider: string;
  model?: string;
  destinationOwnKey: boolean;
}

export type AlertSink = (alert: AlertEvent) => void;

export class AlertEngine {
  constructor(
    private store: Store,
    private sink: AlertSink,
  ) {}

  /** `bodySpans` false for findings scanned over DERIVED text (the rendered
   *  transcript), whose offsets index that text and not the stored body — a
   *  secret the display manufactured by joining blocks has no body span at all.
   *  Recorded span-less rather than wrong; leakSpansFor already skips those. */
  process(call: CallMeta, findings: Finding[], bodySpans = true): void {
    // Dedup keys on the destination PROVIDER (R6) — a mid-session model
    // switch is the same destination and must not re-alert. The model only
    // enriches the human-facing copy, built downstream.
    for (const f of findings) {
      // Some structured values are identifiers, not credential material.
      // The scanner keeps them for conservative capture redaction and overlap
      // suppression, but they must not become a leak event at any surface.
      if (f.alert === false) continue;
      const seenBefore = this.store.fingerprintKnown(f.fingerprint);
      const { fresh, eventId } = this.store.upsertLeakEvent({
        fingerprint: f.fingerprint,
        sessionId: call.sessionId,
        detector: f.detector,
        secretType: f.secretType,
        severity: f.severity,
        confidenceTier: f.tier,
        destination: call.provider,
        callId: call.id,
        ts: Date.now(),
        spanStart: bodySpans ? f.start : undefined, spanEnd: bodySpans ? f.end : undefined,
      });
      if (fresh && f.tier === "structured") {
        this.sink({
          eventId,
          callId: call.id,
          seenBefore,
          secretType: f.secretType,
          agent: call.agent,
          provider: call.provider,
          model: call.model,
          destinationOwnKey: f.destinationOwnKey,
        });
      }
    }
  }
}
