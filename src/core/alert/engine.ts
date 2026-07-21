// Dedup + alert engine (design §6.5). Detection marks everything; alerting
// dedups: upsert on (fingerprint, destination, session) — a fresh row fires
// the loud alert, a conflict silently updates the event. Only the
// structured tier is loud (R5/R6).
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

  process(call: CallMeta, findings: Finding[]): void {
    // Dedup keys on the destination PROVIDER (R6) — a mid-session model
    // switch is the same destination and must not re-alert. The model only
    // enriches the human-facing copy, built downstream.
    for (const f of findings) {
      const seenBefore = this.store.fingerprintKnown(f.fingerprint);
      const { fresh, upgraded, eventId } = this.store.upsertLeakEvent({
        fingerprint: f.fingerprint,
        sessionId: call.sessionId,
        detector: f.detector,
        secretType: f.secretType,
        severity: f.severity,
        confidenceTier: f.tier,
        destination: call.provider,
        callId: call.id,
        ts: Date.now(),
        // A derived finding's offsets index a text that is not this call's
        // stored body, so it gets NO span rather than a wrong one (see Finding).
        spanStart: f.derived ? undefined : f.start,
        spanEnd: f.derived ? undefined : f.end,
      });
      // Fresh, or newly PROVEN: a quiet sighting files the event first (a
      // shape rule, or a finding only a flattened rendering revealed), and the
      // structured proof can arrive a turn later. Without the upgrade arm that
      // proof is silently swallowed — the row exists, so it is never fresh
      // again — and the loudest thing Beagle knows goes unreported.
      if ((fresh || upgraded) && f.tier === "structured") {
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
