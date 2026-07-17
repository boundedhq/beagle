// Beagle dashboard (Preact + htm, buildless — what ships is what's in the
// repo). Rendering rule: captured content is ALWAYS text nodes; nothing from
// the store is ever interpolated into markup (design §6.8). Every stored body
// renders through JsonBody/RawBody from ./render-json.module.js — that module
// is the single place the §6.8 and R7 (secrets always highlighted) rules live.
import { h, render } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import htm from "htm";
import { JsonBody, RawBody } from "./render-json.module.js";

const html = htm.bind(h);

// ---- session bootstrap: exchange the one-time URL token for a header credential ----
let credential = null;
// `beagle ui --session <id>` deep link: land directly on that session's
// transcript. Rides the #fragment so the id never reaches the server.
let deepLinkSession = null;

async function bootstrap() {
  const params = new URLSearchParams(location.search);
  const boot = params.get("boot");
  // Read the fragment BEFORE the history scrub below drops it. Guard the
  // decode: a malformed fragment must be ignored, never blank the dashboard.
  const frag = /^#s=(.+)$/.exec(location.hash);
  if (frag) { try { deepLinkSession = decodeURIComponent(frag[1]); } catch { /* ignore */ } }
  if (boot) history.replaceState(null, "", "/"); // token out of the URL/history
  if (!boot) return false;
  const r = await fetch("/api/session", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ boot }),
  });
  if (!r.ok) return false;
  credential = (await r.json()).credential;
  return true;
}

const api = {
  get: (path) => fetch(path, { headers: { "x-beagle-token": credential } }).then((r) => r.json()),
  post: (path, body) =>
    fetch(path, {
      method: "POST",
      headers: { "x-beagle-token": credential, "content-type": "application/json" },
      body: JSON.stringify(body),
    }).then((r) => r.json()),
};

// ---- components ----

function App() {
  const [calls, setCalls] = useState([]);
  const [leaks, setLeaks] = useState([]);
  const [leaksOnly, setLeaksOnly] = useState(false);
  // A deep link starts on the transcript, with "← sessions" landing on the list.
  const [tab, setTab] = useState(deepLinkSession ? "sessions" : "calls"); // "calls" | "sessions"
  // { id, row } → transcript view. row is the SessionRow when opened from the
  // sessions tab, a { agent, model } sliver from a feed row, or null (from a
  // call detail or deep link) — the transcript header falls back to turn-derived meta.
  const [openSession, setOpenSession] = useState(
    deepLinkSession ? { id: deepLinkSession, row: null } : null,
  );
  const [searchHits, setSearchHits] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [banner, setBanner] = useState(null);
  const [expanded, setExpanded] = useState(null);
  const [stats, setStats] = useState(null); // whole-store totals — the feed is a 500-row window
  const searchBox = useRef(null);

  useEffect(() => {
    api.get("/api/feed").then(setCalls);
    api.get("/api/leaks").then(setLeaks);
    api.get("/api/stats").then(setStats);
    // fetch-SSE: EventSource can't send the credential header (§6.8)
    let stop = false;
    (async () => {
      while (!stop) {
        try {
          const resp = await fetch("/api/stream", { headers: { "x-beagle-token": credential } });
          const reader = resp.body.getReader();
          const dec = new TextDecoder();
          let buf = "";
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            buf += dec.decode(value, { stream: true });
            let i;
            while ((i = buf.indexOf("\n\n")) !== -1) {
              const frame = buf.slice(0, i);
              buf = buf.slice(i + 2);
              handleFrame(frame);
            }
          }
        } catch {
          /* reconnect */
        }
        if (!stop) await new Promise((r) => setTimeout(r, 1500));
      }
    })();
    function handleFrame(frame) {
      const lines = frame.split("\n");
      const ev = lines.find((l) => l.startsWith("event:"))?.slice(6).trim();
      const dataLine = lines.find((l) => l.startsWith("data:"))?.slice(5).trim();
      if (!ev || !dataLine) return;
      const data = JSON.parse(dataLine);
      if (ev === "call") {
        setCalls((xs) => [data, ...xs]);
        api.get("/api/stats").then(setStats);
      }
      if (ev === "alert") {
        setBanner(data);
        api.get("/api/leaks").then(setLeaks);
        api.get("/api/feed").then(setCalls);
        api.get("/api/stats").then(setStats);
      }
      if (ev === "leak") {
        // Silent refresh: possible-tier findings never fire the loud alert
        // frame, but the header count, leak tags, and session chips must not
        // sit stale until a manual reload.
        api.get("/api/leaks").then(setLeaks);
        api.get("/api/feed").then(setCalls);
        api.get("/api/stats").then(setStats);
      }
    }
    return () => { stop = true; };
  }, []);

  async function doSearch(e) {
    e.preventDefault();
    const term = searchBox.current?.value ?? "";
    setSearchTerm(term);
    setSearchHits(term ? await api.post("/api/search", { term }) : null);
  }

  const visible = calls.filter((x) => !leaksOnly || x.hasLeak);
  // Server totals count the whole store; the feed state is only its newest
  // 500-row window. Fall back to the window while /api/stats is in flight.
  const callCount = stats?.calls ?? calls.length;
  const sessionCount = stats?.sessions ?? new Set(calls.map((x) => x.sessionId)).size;
  const agentCount = stats?.agents ?? new Set(calls.map((x) => x.agent).filter(Boolean)).size;

  return html`
    <header>
      <div class="brand">
        <div class="badge" aria-hidden="true">
          <!-- the beagle mark — keep in sync with docs/assets/beagle.svg (same paths, minus the tile) -->
          <svg class="dog" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
            <path d="M13 59 C13 50 20.5 44.5 32 44.5 C43.5 44.5 51 50 51 59 Z" fill="#46311f"></path>
            <path d="M23 59 C23 49.5 27 46 32 46 C37 46 41 49.5 41 59 Z" fill="#e2d2ba"></path>
            <path d="M24 20 C15 16 8.8 23 8.8 32 C8.8 42 11.5 51 17.5 54 C21.5 55.8 24.6 52.5 24.8 46 C25 38 24.6 27 24 20 Z" fill="#7a4a28"></path>
            <path d="M40 20 C49 16 55.2 23 55.2 32 C55.2 42 52.5 51 46.5 54 C42.5 55.8 39.4 52.5 39.2 46 C39 38 39.4 27 40 20 Z" fill="#7a4a28"></path>
            <ellipse cx="32" cy="29.5" rx="16.5" ry="17.5" fill="#c98f4e"></ellipse>
            <path d="M28.7 12.7 C27.9 17 27.3 26 27.2 35 L36.8 35 C36.7 26 36.1 17 35.3 12.7 C33.1 12 30.9 12 28.7 12.7 Z" fill="#f2e8d8"></path>
            <ellipse cx="32" cy="41" rx="10.5" ry="8.5" fill="#f2e8d8"></ellipse>
            <circle cx="24.5" cy="29.5" r="2.8" fill="#26201a"></circle>
            <circle cx="39.5" cy="29.5" r="2.8" fill="#26201a"></circle>
            <circle cx="23.6" cy="28.6" r="0.95" fill="#f2e8d8"></circle>
            <circle cx="38.6" cy="28.6" r="0.95" fill="#f2e8d8"></circle>
            <path d="M27.9 37.5 C27.9 35.9 29.6 35.2 32 35.2 C34.4 35.2 36.1 35.9 36.1 37.5 C36.1 39.6 34 41.2 32 41.2 C30 41.2 27.9 39.6 27.9 37.5 Z" fill="#26201a"></path>
            <ellipse cx="30.6" cy="36.7" rx="1.1" ry="0.7" fill="#f2e8d8" fill-opacity="0.35"></ellipse>
            <path d="M32 41.2 L32 43.4 M32 43.4 C30.8 45.4 28.8 45.4 27.6 44 M32 43.4 C33.2 45.4 35.2 45.4 36.4 44"
              stroke="#26201a" stroke-width="1.4" stroke-linecap="round" fill="none"></path>
          </svg>
        </div>
        <div class="brand-text">
          <h1>beagle<span class="cursor" aria-hidden="true">_</span></h1>
          <p class="tagline">
            sees what your AI agents send to model providers — and${" "}
            <span class="hl">flags leaked secrets</span>
          </p>
        </div>
      </div>
      <div class="stats">
        <button aria-live="polite"
          class=${(leaks.length ? "stat leak" : "stat leak zero") + " clickable"}
          title=${leaks.length
            ? "filter the feed to calls that leaked a secret"
            : "no secrets detected in anything captured so far"}
          onClick=${() => { setOpenSession(null); setTab("calls"); setLeaksOnly(true); }}>
          <span class="leak-dot" aria-hidden="true"></span>
          <div class="stat-col">
            <span class="num">${leaks.length}</span>
            <span class="label">leak${leaks.length === 1 ? "" : "s"}</span>
          </div>
        </button>
        <button class="stat clickable" title="show every captured call"
          onClick=${() => { setOpenSession(null); setLeaksOnly(false); setTab("calls"); }}>
          <span class="num">${callCount}</span>
          <span class="label">call${callCount === 1 ? "" : "s"}</span>
        </button>
        <button class="stat clickable" title="browse sessions"
          onClick=${() => { setOpenSession(null); setTab("sessions"); }}>
          <span class="num">${sessionCount}</span>
          <span class="label">session${sessionCount === 1 ? "" : "s"}</span>
        </button>
        <div class="stat" title="distinct agents seen">
          <span class="num">${agentCount}</span>
          <span class="label">agent${agentCount === 1 ? "" : "s"}</span>
        </div>
      </div>
      <div class="actions">
        <form role="search" class="search" onSubmit=${doSearch}>
          <svg class="search-icon" aria-hidden="true" width="14" height="14" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round">
            <circle cx="10.5" cy="10.5" r="6.5"></circle>
            <path d="M20 20l-4.6-4.6"></path>
          </svg>
          <input ref=${searchBox} type="search" placeholder="was this ever sent?"
            aria-label="search everything captured"
            title="literal search over everything captured — exact text, not fuzzy" />
        </form>
        <button class=${leaksOnly ? "toggle active" : "toggle"}
          aria-pressed=${leaksOnly ? "true" : "false"}
          onClick=${() => setLeaksOnly(!leaksOnly)}>
          <span class="toggle-dot" aria-hidden="true"></span>leaks only
        </button>
      </div>
    </header>
    <nav class="tabs" role="tablist">
      <button role="tab" aria-selected=${tab === "calls" && !openSession ? "true" : "false"}
        class=${tab === "calls" && !openSession ? "tab active" : "tab"}
        onClick=${() => { setTab("calls"); setOpenSession(null); }}>calls</button>
      <button role="tab" aria-selected=${tab === "sessions" || openSession ? "true" : "false"}
        class=${tab === "sessions" || openSession ? "tab active" : "tab"}
        onClick=${() => { setTab("sessions"); setOpenSession(null); }}>sessions${
          sessionCount > 0 ? html` <span class="tab-count">${sessionCount}</span>` : ""
        }</button>
    </nav>
    <main>
      ${banner &&
      html`<div class="banner" onClick=${() => setBanner(null)}>
        ▲ ${banner.title}${banner.subtitle ? ` — ${banner.subtitle}` : ""} — ${banner.body}
      </div>`}
      ${searchHits !== null && html`<${SearchResults} hits=${searchHits} term=${searchTerm}
        onClear=${() => setSearchHits(null)}
        onOpen=${(id) => { setTab("calls"); setOpenSession(null); setExpanded(id); }} />`}
      ${openSession != null &&
      html`<${SessionTranscript} sessionId=${openSession.id} row=${openSession.row}
        onBack=${() => setOpenSession(null)}
        onPurged=${() => {
          setOpenSession(null); // the session is gone — leave the transcript
          api.get("/api/feed").then(setCalls);
          api.get("/api/leaks").then(setLeaks);
          api.get("/api/stats").then(setStats);
        }} />`}
      ${openSession == null && tab === "sessions" &&
      html`<${Sessions} leaksOnly=${leaksOnly}
        onOpen=${(s) => setOpenSession({ id: s.sessionId, row: s })} />`}
      ${openSession == null && tab === "calls" && html`
        ${visible.length === 0 && html`<div class="empty">
          no calls${leaksOnly ? " with leaks" : ""} yet — run an agent under
          ${" "}<code>beagle run</code> and its traffic appears here live<br />
          <span class="hint">each call links to its session's full conversation —
          click the › in the session column</span>
        </div>`}
        ${visible.length > 0 &&
        html`<div class="row head" aria-hidden="true">
          <span class="dot spacer"></span>
          <span class="time">time</span>
          <span class="agent">agent</span>
          <span class="model">model</span>
          <span class="summary">what was sent</span>
          <span class="session">session</span>
        </div>`}
        ${visible.map(
          (x) => html`
            <${Row} key=${x.id} x=${x}
              onToggle=${() => setExpanded(expanded === x.id ? null : x.id)}
              onSession=${() =>
                setOpenSession({ id: x.sessionId, row: { agent: x.agent, model: x.model } })} />
            ${expanded === x.id &&
            html`<${Detail} id=${x.id}
              onSession=${(sid) => setOpenSession({ id: sid, row: null })} />`}
          `,
        )}
      `}
    </main>
    <footer>
      🔒 everything on this page stays on your machine — the only outbound traffic is your
      agents' own calls to their model providers. No telemetry. The viewer serves loopback
      only, token-protected, while this tab is open.
    </footer>
  `;
}

function Row({ x, onToggle, onSession }) {
  const t = new Date(x.tsRequest).toLocaleTimeString();
  return html`
    <div class=${x.hasLeak ? "row leak" : "row"} onClick=${onToggle}>
      <span
        class=${x.status == null ? "dot pending" : x.status >= 400 ? "dot err" : "dot"}
        title=${x.status == null
          ? "no response recorded"
          : x.status >= 400
            ? `provider returned ${x.status}`
            : "call succeeded"}
      ><span class="sr-only">${x.status == null
        ? "no response recorded"
        : x.status >= 400 ? `error ${x.status}` : "ok"}</span></span>
      <span class="time">${t}</span>
      <span class="agent">${x.agent ?? "?"}</span>
      <span class="model">${x.model ?? ""}</span>
      <span class="summary">${x.summary ?? "(no summary)"}</span>
      ${x.hasLeak && html`<span class="chip leak">leak</span>`}
      ${x.source === "wire"
        ? html`<span class="chip wire"
            title="Beagle's proxy saw these exact bytes go to the provider">✓ observed</span>`
        : html`<span class="chip otel"
            title=${"the agent's own report of what it sent — Beagle did not see the wire, " +
              "so this is a self-report and its alerts can lag a few seconds"}>self-reported</span>`}
      ${x.scanState !== "ok" && html`<span class="chip">scan incomplete</span>`}
      <span class="session">
        <button class="session-link" title=${`${x.sessionId} — open this session as a conversation`}
          onClick=${(e) => { e.stopPropagation(); onSession(); }}>
          ${x.sessionId.slice(0, 12)}<span class="go" aria-hidden="true"> ›</span>
        </button>
      </span>
    </div>
  `;
}

// The sessions tab: one row per session, newest activity first. The header's
// "leaks only" toggle narrows this the same way it narrows the calls feed —
// to sessions that leaked at least one secret.
function Sessions({ onOpen, leaksOnly }) {
  const [sessions, setSessions] = useState(null);
  useEffect(() => { api.get("/api/sessions").then(setSessions); }, []);
  if (sessions === null) return html`<div class="empty">loading…</div>`;
  if (sessions.length === 0)
    return html`<div class="empty">
      no sessions yet — run an agent under <code>beagle run</code> and each
      conversation shows up here. Click one to read it end to end.
    </div>`;
  const shown = sessions.filter((s) => !leaksOnly || s.leaks > 0);
  if (shown.length === 0)
    return html`<div class="empty">
      no sessions leaked a secret — turn off <span class="hl">leaks only</span>${" "}
      to see all ${sessions.length} session${sessions.length === 1 ? "" : "s"}.
    </div>`;
  return html`
    ${shown.map((s) => {
      const span = spanLabel(s.firstTs, s.lastTs);
      const title = sessionTitle(s.title);
      return html`<div class=${s.leaks > 0 ? "srow leak" : "srow"} key=${s.sessionId}
        onClick=${() => onOpen(s)} title="open this session as a conversation">
        <span class=${s.leaks > 0 ? "dot err" : "dot"}></span>
        <div class="scol">
          <div class="stitle-line">
            <span class=${title ? "stitle" : "stitle untitled"}
              title=${title || "no opening prompt captured"}>${title || "untitled session"}</span>
            ${s.utility && s.calls === 1 &&
            html`<span class="chip"
              title=${"a single stateless one-shot request (opencode fires these to name a " +
                "conversation) — it carries no identity linking it to the conversation it " +
                "titled, so it can't be merged into it"}>title turn</span>`}
            ${s.leaks > 0 &&
            html`<span class="chip leak">${s.leaks} leak${s.leaks === 1 ? "" : "s"}</span>`}
            ${s.source !== "wire" &&
            html`<span class="chip otel">${
              s.source === "mixed" ? "partly self-reported" : "self-reported"}</span>`}
          </div>
          <div class="smeta">
            <span class="s-agent">${s.agent ?? "?"}</span>
            <span aria-hidden="true">·</span>
            <span>${s.calls} call${s.calls === 1 ? "" : "s"}</span>
            ${span && html`<span aria-hidden="true">·</span><span>${span}</span>`}
            ${s.model &&
            html`<span class="s-model"><span aria-hidden="true">· </span>${s.model}</span>`}
            <span aria-hidden="true">·</span>
            <span>${fmtDivider(s.lastTs, true)}</span>
          </div>
        </div>
        <span class="s-go">view session ›</span>
      </div>`;
    })}
    ${sessions.length >= 200 &&
    html`<div class="empty">showing the 200 most recently active sessions</div>`}
  `;
}

// A session's display title from its opening call summary. Claude Code's first
// call is a title-generation turn whose summary is literally {"title":"…"} —
// unwrap that to the clean title; other agents' summaries are plain text and
// pass through. Already secret-scrubbed at capture, so nothing to sanitize.
function sessionTitle(raw) {
  const t = (raw ?? "").trim();
  if (t.startsWith("{")) {
    try {
      const o = JSON.parse(t);
      // A {title: "..."} wrapper always yields its title — even when empty,
      // so it collapses to "untitled" rather than showing the raw JSON.
      if (o && typeof o.title === "string") return o.title.trim();
    } catch { /* not a JSON title wrapper — use as-is */ }
  }
  return t;
}

// Plain-English name for a detector tag, so the leak chip reads "API key",
// not "generic-api-key". Known types get a curated label (the generic
// high-entropy match is just "API key" — the detector can't say what kind);
// anything unmapped de-kebabs to a readable phrase. Mirrors secretName() in
// the notifier so the banner and the detail view speak the same words.
const SECRET_LABELS = {
  "aws-access-key-id": "AWS access key",
  "aws-secret-access-key": "AWS secret key",
  "github-pat": "GitHub personal access token",
  "github-oauth": "GitHub OAuth token",
  "github-app-token": "GitHub app token",
  "stripe-access-token": "Stripe API key",
  "slack-bot-token": "Slack bot token",
  "slack-user-token": "Slack user token",
  "gcp-api-key": "Google Cloud API key",
  "openai-api-key": "OpenAI API key",
  "anthropic-api-key": "Anthropic API key",
  "private-key": "private key",
  "jwt": "JWT token",
  "generic-api-key": "API key",
};
function secretLabel(type) {
  if (typeof type !== "string" || type === "") return "secret";
  // Object.hasOwn, not a bare index: a prototype key ("toString") would
  // otherwise return an inherited value instead of de-kebabbing.
  return Object.hasOwn(SECRET_LABELS, type) ? SECRET_LABELS[type] : type.replace(/-/g, " ");
}

// One session rendered as a chronological conversation thread — each turn
// shows only what it ADDED (the server diffs wire histories), flowing as one
// continuous document: time dividers on gaps, a metadata rail per turn, then
// the messages (tinted user box, flat assistant text, collapsible tool cards).
function SessionTranscript({ sessionId, row, onBack, onPurged }) {
  const [view, setView] = useState(null);
  const [openCall, setOpenCall] = useState(null);
  const [confirmDel, setConfirmDel] = useState(false);
  const [deleting, setDeleting] = useState(false);
  useEffect(() => { api.get(`/api/session/${sessionId}`).then(setView); }, [sessionId]);

  async function purgeSession() {
    setDeleting(true);
    try {
      const r = await api.post("/api/purge", { kind: "session", sessionId });
      if (r?.ok) { onPurged?.(); return; } // component unmounts; no state left to reset
    } catch { /* network drop — fall through and reset so it isn't stuck */ }
    setDeleting(false);
    setConfirmDel(false);
  }
  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onBack(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey); // else it fires on the list view
  }, [onBack]);
  if (!view) return html`<div class="empty">loading…</div>`;
  const turns = view.turns ?? [];

  // Header meta: prefer the SessionRow the user clicked; fall back to what the
  // turns themselves say (opened from a call detail, where there is no row).
  const agent = row?.agent ?? "session";
  const model = row?.model ?? [...turns].reverse().find((t) => t.model)?.model;
  const firstTs = row?.firstTs ?? turns[0]?.tsRequest;
  const lastTs = row?.lastTs ?? turns.at(-1)?.tsRequest;
  const source =
    row?.source ?? (new Set(turns.map((t) => t.source)).size > 1 ? "mixed" : turns[0]?.source);
  const mixed = source === "mixed";
  const secretCount = new Set(turns.flatMap((t) => t.leaks.map((l) => l.value))).size;
  const span = firstTs != null && lastTs != null ? spanLabel(firstTs, lastTs) : "";

  return html`
    <div class="transcript">
      <div class="transcript-head">
        <button onClick=${onBack} title="back to the list (Esc)">← sessions</button>
        <span class="agent-name">${agent}</span>
        <${CopyChip} value=${sessionId} />
        <div class="th-actions">
          ${!confirmDel
            ? html`<button class="danger-link"
                title="permanently erase everything Beagle captured in this session"
                onClick=${() => setConfirmDel(true)}>🗑 delete session</button>`
            : html`<span class="confirm">
                <span class="confirm-q">delete this session for good?</span>
                <button onClick=${() => setConfirmDel(false)} disabled=${deleting}>cancel</button>
                <button class="danger" onClick=${purgeSession} disabled=${deleting}>
                  ${deleting ? "deleting…" : "delete"}
                </button>
              </span>`}
        </div>
      </div>
      <div class="transcript-meta">
        ${model ? html`<span>${model}</span><span aria-hidden="true">·</span>` : ""}
        <span>${turns.length} turn${turns.length === 1 ? "" : "s"}</span>
        ${span && html`<span aria-hidden="true">·</span><span>over ${span}</span>`}
        ${firstTs != null &&
        html`<span aria-hidden="true">·</span><span>started ${new Date(firstTs).toLocaleString()}</span>`}
        ${source === "wire" &&
        html`<span class="chip wire" title="Beagle's proxy saw these exact bytes">✓ observed</span>`}
        ${source === "otel" &&
        html`<span class="chip otel" title="the agent's own report — Beagle did not see the wire">self-reported</span>`}
        ${mixed && html`<span class="chip otel">partly self-reported</span>`}
        ${view.utility && turns.length === 1 &&
        html`<span class="chip" title="a single stateless one-shot fired to name a conversation">title turn</span>`}
        ${secretCount > 0 &&
        html`<span class="chip leak">${secretCount} secret${secretCount === 1 ? "" : "s"}</span>`}
        ${view.truncated && html`<span class="warn">showing the first 200 calls only</span>`}
      </div>
      ${view.system != null && html`<${SystemCard} text=${view.system} />`}
      ${turns.length === 0 && html`<div class="empty">nothing captured in this session yet</div>`}
      <div class="thread">
        ${turns.map((t, i) => {
          const prev = turns[i - 1];
          const dayChanged =
            prev && new Date(prev.tsRequest).toDateString() !== new Date(t.tsRequest).toDateString();
          const showDivider = !prev || dayChanged || t.tsRequest - prev.tsRequest > 120_000;
          const showDate = !prev || dayChanged;
          const modelChanged = t.model && t.model !== prev?.model;
          const hasLeak = t.leaks.length > 0;
          const open = openCall === t.id;
          return html`
            <div class=${hasLeak ? "turn has-leak" : "turn"} key=${t.id}>
              ${showDivider && html`<div class="time-divider">${fmtDivider(t.tsRequest, showDate)}</div>`}
              <div class="turn-rail" onClick=${() => setOpenCall(open ? null : t.id)}
                title="click for this call's full detail (raw bytes, sizes, tokens)">
                <span>${new Date(t.tsRequest).toLocaleTimeString()}</span>
                ${modelChanged && html`<span aria-hidden="true">·</span><span>${t.model}</span>`}
                ${mixed && t.source !== "wire" && html`<span class="chip otel">self-reported</span>`}
                ${t.status != null && t.status >= 400 && html`<span class="err">error ${t.status}</span>`}
                ${hasLeak && html`<span class="chip leak">secret sent</span>`}
                <span class="turn-toggle">${open ? "▾ details" : "▸ details"}</span>
              </div>
              ${open && html`<${Detail} id=${t.id} />`}
              ${t.messages.map(
                (m, j) => html`<${TMsg} key=${`${t.id}:${j}`} m=${m} leaks=${t.leaks} />`,
              )}
              ${t.responseText != null && t.responseText !== "" &&
              html`<${TMsg} key=${`${t.id}:resp`} leaks=${t.leaks}
                m=${{ role: "response", content: t.responseText }} />`}
              ${t.messages.length === 0 && !t.responseText &&
              html`<div class="turn-empty">(no parsed content — open details for raw bytes)</div>`}
            </div>
          `;
        })}
      </div>
    </div>
  `;
}

// "3:42 PM" between turns; "Jul 15, 3:42 PM" with the date (first turn / day
// change / session meta). The year is added only for a non-current-year date,
// so a session from last year isn't ambiguous while recent ones stay clean.
function fmtDivider(ts, withDate) {
  const d = new Date(ts);
  const time = d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  if (!withDate) return time;
  const opts = { month: "short", day: "numeric" };
  if (d.getFullYear() !== new Date().getFullYear()) opts.year = "numeric";
  return `${d.toLocaleDateString([], opts)}, ${time}`;
}

// The session id as a copyable chip: title carries the full id, click copies.
function CopyChip({ value }) {
  const [copied, setCopied] = useState(false);
  return html`<button class="chip copy-chip" title=${value}
    onClick=${async () => {
      try {
        await navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      } catch { /* title still exposes the full id */ }
    }}>${copied ? "copied" : value.slice(0, 8)}</button>`;
}

// The session's system prompt, collapsed to one line until asked for.
function SystemCard({ text }) {
  const [open, setOpen] = useState(false);
  return html`
    <div class="syscard">
      <div class="sys-head" onClick=${() => setOpen(!open)}>
        ${open ? "▾" : "▸"} system prompt
      </div>
      ${open && html`<pre>${text}</pre>`}
    </div>
  `;
}

// One transcript message. Uniform cards: every message — user, assistant,
// tool, request — sits in the same bordered card, differentiated only by the
// colored role label in its header. Tool/request cards additionally collapse.
// All bodies render through JsonBody (see render-json.module.js).
function TMsg({ m, leaks }) {
  const content = typeof m.content === "string" ? m.content : JSON.stringify(m.content, null, 2);
  // The one unacceptable failure is a hidden secret: a leak-bearing message
  // never clamps and never renders collapsed.
  const hasLeak = (leaks ?? []).some((l) => l.value && content.includes(l.value));
  if (m.role === "tool" || m.role === "request") {
    return html`<${ToolCard} role=${m.role} content=${content} leaks=${leaks} hasLeak=${hasLeak} />`;
  }
  // user / response / assistant-history / any future role: same card, labeled
  // header; bodies get the same JSON pretty-printing as tool cards.
  return html`
    <div class=${hasLeak ? "mcard has-leak" : "mcard"}>
      <div class="mc-head"><span class=${`mc-name ${m.role}`}>${m.role}</span></div>
      <div class="mc-body">
        <${JsonBody} content=${content} leaks=${leaks}
          threshold=${m.role === "user" ? 1500 : 2500} hasLeak=${hasLeak} />
      </div>
    </div>
  `;
}

// A tool call / tool output (or a legacy "request" blob) in the same card
// shell as every other message: always-visible header (glyph, name, one-line
// preview), body only when opened, JSON pretty-printed for reading. Long cards
// start collapsed — unless they carry a secret, which forces them open.
function ToolCard({ role, content, leaks, hasLeak }) {
  const startOpen = hasLeak || content.length <= 240;
  const [open, setOpen] = useState(startOpen);
  const isRequest = role === "request";
  // Display-only parse of the "Name: payload" convention the mappers write.
  // Hostile content can at most mislabel its own card — never inject markup.
  const match = isRequest ? null : content.match(/^([A-Za-z_][\w.-]{0,40}):\s/);
  const name = isRequest ? "request" : (match?.[1] ?? "tool");
  const payload = match ? content.slice(match[0].length) : content;
  const collapsible = !startOpen || hasLeak || content.length > 240;
  return html`
    <div class=${hasLeak ? "mcard has-leak" : "mcard"}
      title=${isRequest
        ? "what the agent reported sending — prompt and tool inputs as one block"
        : undefined}>
      <div class=${collapsible ? "mc-head click" : "mc-head"}
        onClick=${() => collapsible && setOpen(!open)}>
        <span aria-hidden="true">${isRequest ? "⇢" : "⚙"}</span>
        <span class=${`mc-name ${isRequest ? "request" : "tool"}`}>${name}</span>
        ${!open && html`<span class="mc-preview">${payload.slice(0, 200)}</span>`}
        ${hasLeak && html`<span class="chip leak">secret</span>`}
        ${collapsible && html`<span class="mc-chev" aria-hidden="true">${open ? "▾" : "▸"}</span>`}
      </div>
      ${open &&
      html`<div class="mc-body scroll">
        <${JsonBody} content=${payload} leaks=${leaks} threshold=${1e9} hasLeak=${hasLeak} />
      </div>`}
    </div>
  `;
}

// "3 min", "2 h" — how long a session's activity spans, for the sessions list.
function spanLabel(first, last) {
  const s = Math.round((last - first) / 1000);
  if (s < 60) return s > 1 ? `${s} s` : "";
  if (s < 3600) return `${Math.round(s / 60)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

function Detail({ id, onSession }) {
  const [detail, setDetail] = useState(null);
  const [raw, setRaw] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  useEffect(() => { api.get(`/api/call/${id}`).then(setDetail); }, [id]);
  if (!detail) return html`<div class="detail">loading…</div>`;
  if (detail.error) return html`<div class="detail">${detail.error}</div>`;

  // The server assembles the readable structure (detail.ts): parsed messages,
  // reassembled response text, and the secret strings to highlight. Legacy
  // Mode B rows (captured before display_messages existed) parse to no
  // structured messages — show their captured request as a "request" card
  // rather than dumping the user into the raw <pre> view (mirrors the
  // transcript's legacy fallback). The raw-bytes toggle still shows true bytes.
  const messages = detail.messages?.length
    ? detail.messages
    : detail.source === "otel" && detail.requestRaw
      ? [{ role: "request", content: detail.requestRaw }]
      : [];
  const system = detail.system;
  const leaks = detail.leaks ?? [];
  const older = messages.slice(0, -1);
  const newest = messages.slice(-1);
  // An earlier message that holds a leak must never sit behind the collapsed
  // fold — R7: detected secrets are ALWAYS visibly highlighted. When one does,
  // show the whole history inline (correctness beats brevity here).
  const leakInOlder = older.some((m) => leaks.some((l) => l.value && String(m.content ?? "").includes(l.value)));
  const showOlderInline = older.length <= 3 || leakInOlder;
  // Nothing structured → raw is the only honest view; don't show an empty
  // timeline with a toggle the user has to discover.
  const hasStructure = messages.length > 0 || system != null;
  const showRaw = raw || !hasStructure;
  // What the readable view actually HIGHLIGHTS inline: the messages (earlier
  // ones holding a leak are force-shown, above) and the response. NOT the
  // system prompt — it sits in a collapsed, un-highlighted chip — and NOT
  // anything only in a header or protocol field. If the secret lives only in
  // those, the readable view shows no highlight, so point the user at raw.
  const readableText = [...messages.map((m) => m.content), detail.responseText ?? ""].join("\n");
  const leakHiddenInRaw = leaks.length > 0 && !showRaw && leaks.every((l) => !readableText.includes(l.value));

  return html`
    <div class="detail">
      <div class="meta">
        <div class="meta-primary">
          <span class="agent-name">${detail.agent ?? "?"}</span>
          <span class="arrow" aria-hidden="true">→</span>
          <span class="to">${detail.provider ?? "?"}${detail.model ? " · " + detail.model : ""}</span>
          ${detail.source === "wire"
            ? html`<span class="chip wire"
                title="Beagle's proxy saw these exact bytes go to the provider">✓ observed</span>`
            : html`<span class="chip otel"
                title=${"the agent's own report of what it sent — Beagle did not see the wire, " +
                  "so this is a self-report and its alerts can lag a few seconds"}>self-reported</span>`}
          ${detail.status != null && detail.status >= 400 &&
          html`<span class="err">error ${detail.status}</span>`}
        </div>
        <div class="meta-sub">
          <span class="k">call</span> <${CopyChip} value=${detail.id} />
          ${(detail.tokensIn != null || detail.tokensOut != null) &&
          html`<span aria-hidden="true">·</span>
            <span class="toks" title="input → output tokens">${tok(detail.tokensIn)} → ${tok(detail.tokensOut)} tokens</span>`}
        </div>
        <div class="meta-sub">
          <span class="k">session</span> <${CopyChip} value=${detail.sessionId} />
          <span aria-hidden="true">·</span>
          <span class="k">grouped by</span> <span>${groupedBy(detail.sessionTier)}</span>
          ${onSession &&
          html`<span aria-hidden="true">·</span>
            <button class="linklike"
              onClick=${() => onSession(detail.sessionId)}>view session →</button>`}
        </div>
        ${detail.captureState !== "ok" &&
        html`<div class="warn">⚠ capture truncated — the stored bytes are incomplete</div>`}
        ${detail.scanState !== "ok" &&
        html`<div class="warn">⚠ scan incomplete — this body was not fully verified, not marked clean</div>`}
      </div>
      ${leaks.length > 0 &&
      html`<div class="leakbar">
        🔴 ${leaks.length} secret${leaks.length === 1 ? "" : "s"} sent in this call —
        ${leakHiddenInRaw ? "not in the readable messages (it's in a header, the system prompt, or a protocol field) — open raw to see it highlighted:" : "highlighted below:"}
        ${leaks.map((l) => html`<span class="chip leak">${secretLabel(l.secretType)}</span>`)}
      </div>`}
      ${hasStructure &&
      html`<div class="viewswitch">
        <div class="viewtoggle" role="group" aria-label="detail view">
          <button class=${!showRaw ? "active" : ""} aria-pressed=${!showRaw ? "true" : "false"}
            onClick=${() => setRaw(false)}>readable</button>
          <button class=${showRaw ? "active" : ""} aria-pressed=${showRaw ? "true" : "false"}
            onClick=${() => setRaw(true)}>raw</button>
        </div>
        ${showRaw &&
        html`<span class="viewhint">${detail.source === "wire"
          ? "the exact request and response Beagle saw on the wire"
          : "the request and response the agent reported sending"}</span>`}
      </div>`}
      ${showRaw
        ? html`
            <h4 class="req">request</h4>
            <${RawBody} body=${detail.requestRaw} leaks=${leaks} />
            <h4 class="resp">response</h4>
            <${RawBody} body=${detail.responseRaw} leaks=${leaks} />
            ${detail.sseRaw &&
            html`<h4>raw stream (as received)</h4><pre>${detail.sseRaw}</pre>`}
          `
        : html`
            ${system != null &&
            html`<${Chip} label="system prompt" body=${system} />`}
            ${older.length > 0 && showOlderInline
              ? older.map((m) => html`<${Msg} m=${m} leaks=${leaks} />`)
              : html`
                  ${older.length > 3 &&
                  html`<div class="folded history-fold" onClick=${() => setHistoryOpen(!historyOpen)}>
                    ${historyOpen ? "▾ hide" : "▸ show"} the ${older.length} earlier messages
                  </div>`}
                  ${historyOpen && older.map((m) => html`<${Msg} m=${m} leaks=${leaks} />`)}
                `}
            ${newest.map((m) => html`<${Msg} m=${m} leaks=${leaks} />`)}
            ${detail.responseText != null &&
            html`<${Msg} m=${{ role: "response", content: detail.responseText }} leaks=${leaks} />`}
          `}
    </div>
  `;
}

// Same collapsible card the transcript uses for its system prompt — one
// visual for one concept, on both screens.
function Chip({ label, body }) {
  const [open, setOpen] = useState(false);
  return html`
    <div class="syscard">
      <div class="sys-head" onClick=${() => setOpen(!open)}>${open ? "▾" : "▸"} ${label}</div>
      ${open && html`<pre>${body}</pre>`}
    </div>
  `;
}

function Msg({ m, leaks }) {
  const content =
    typeof m.content === "string" ? m.content : JSON.stringify(m.content, null, 2);
  return html`
    <div class=${"msg " + m.role}>
      <div class="role">${m.role}</div>
      <div><${JsonBody} content=${content} leaks=${leaks} threshold=${1e9} /></div>
    </div>
  `;
}

function SearchResults({ hits, term, onClear, onOpen }) {
  return html`
    <div class="searchresults">
      <div>
        ${hits.length === 0
          ? html`<strong>no matches — never sent.</strong>`
          : html`<strong>
              found in ${hits.length} call${hits.length === 1 ? "" : "s"} across
              ${" " + new Set(hits.map((h) => h.sessionId)).size} session(s)
            </strong>`}
        ${" "}<button onClick=${onClear}>clear</button>
      </div>
      ${hits.map(
        (hit) => html`
          <div class="hit">
            <a href="#" onClick=${(e) => { e.preventDefault(); onOpen(hit.callId); }}>
              ${hit.callId.slice(0, 8)}
            </a>
            ${" "}${new Date(hit.tsRequest).toLocaleString()} · session ${hit.sessionId.slice(0, 12)}
            · <mark>${term}</mark>
          </div>
        `,
      )}
    </div>
  `;
}

// Plain-language read of HOW a call was grouped into its session (the
// resolver's tier), not an internal tag like "conv-id". The confidence
// qualifier shows only when it ISN'T high — a high-confidence grouping needs
// no caveat; a weaker one earns the disclosure.
function groupedBy(tier) {
  switch (tier) {
    case "conv-id": return "the request's conversation id";
    case "prefix": return "matching message history";
    case "compaction-link": return "history matched across a compaction (medium confidence)";
    case "run": return "the same run, no history match (lower confidence)";
    case "time-gap": return "recent activity — a best guess (low confidence)";
    default: return tier;
  }
}

const tok = (n) => (n == null ? "?" : n.toLocaleString());

// ---- mount ----
bootstrap().then((ok) => {
  const root = document.getElementById("app");
  if (!ok) {
    render(
      html`<div class="empty">
        This viewer session has expired (the one-time link was already used).<br />
        Run <code>beagle ui</code> to get a fresh link.
      </div>`,
      root,
    );
    return;
  }
  render(html`<${App} />`, root);
});
