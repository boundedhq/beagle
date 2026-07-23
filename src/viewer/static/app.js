// Beagle dashboard (Preact + htm, buildless — what ships is what's in the
// repo). Rendering rule: captured content is ALWAYS text nodes; nothing from
// the store is ever interpolated into markup (design §6.8). Every stored body
// renders through JsonBody/RawBody from ./render-json.module.js — that module
// is the single place the §6.8 and R7 (secrets always highlighted) rules live.
import { h, render } from "preact";
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import htm from "htm";
import { Highlighted, JsonBody, RawBody, hasFind } from "./render-json.module.js";

const html = htm.bind(h);

// Window-level Escape handlers back out of a VIEW — but while focus is in a
// form field, Escape belongs to the field (clearing a search input must not
// also tear down the screen behind it).
const isTypingTarget = (e) => /^(?:INPUT|TEXTAREA|SELECT)$/.test(e.target?.tagName ?? "");

// ---- session bootstrap: exchange the one-time URL token for a header credential ----
let credential = null;
// Tab-scoped: survives reload, disappears when the tab closes, and never
// enters the URL. localStorage would outlive the viewer tab and is not used.
const SESSION_CREDENTIAL_KEY = "beagle.viewerCredential";
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
  let saved = null;
  try { saved = sessionStorage.getItem(SESSION_CREDENTIAL_KEY); } catch { /* unavailable */ }
  if (!boot && !saved) return false;
  // Send a saved credential AND (if present) the boot body in one request: the
  // server checks the x-beagle-token header before the boot body, so a live tab
  // credential keeps the session even when a stale one-time link is re-opened
  // beside it — never dropping a working session or needlessly spending the
  // boot token. Boot is the fallback when there is no saved credential (first
  // load) or the server rejects it. A rejected fetch (viewer stopped) throws
  // out of here and the caller renders the notice — not a blank page.
  const headers = {};
  let body;
  if (saved) headers["x-beagle-token"] = saved;
  if (boot) { headers["content-type"] = "application/json"; body = JSON.stringify({ boot }); }
  const r = await fetch("/api/session", { method: "POST", headers, body });
  if (!r.ok) {
    // A saved credential the server rejected is stale (viewer restarted/rotated)
    // — drop it so the next load doesn't retry a dead value. A rejected fetch
    // (unreachable) never reaches here, so an offline reload keeps the credential
    // to retry once the viewer is back.
    if (saved) { try { sessionStorage.removeItem(SESSION_CREDENTIAL_KEY); } catch { /* unavailable */ } }
    return false;
  }
  credential = await r.json().then((d) => d?.credential).catch(() => null);
  if (!credential) return false; // never persist/authorize an empty or non-JSON credential
  try { sessionStorage.setItem(SESSION_CREDENTIAL_KEY, credential); } catch { /* unavailable */ }
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
  // Active search: { term, hits, truncated } | null. While set, the search
  // view REPLACES the main content; the tab/transcript state underneath is
  // left alone, so clearing lands the user back exactly where they were.
  const [search, setSearch] = useState(null);
  const [banner, setBanner] = useState(null);
  const [expanded, setExpanded] = useState(null);
  const [stats, setStats] = useState(null); // whole-store totals — the feed is a 500-row window
  // { id, sessionId, n } — the last row that gained a response in place. The
  // counter is what makes a repeat stitch on the SAME row a new value; the
  // views below select on id/sessionId and pass 0 when it isn't theirs.
  // That means a stitch elsewhere flips an open pane's prop back to 0, costing
  // it one extra refetch — bounded (once per pane per stitch of its own row,
  // and only while it is open) and deliberately preferred over a per-id map
  // that would grow for the tab's lifetime. It never MISSES a refresh, which
  // is the direction that matters: n only ever increases, so a stitch naming
  // this view always changes its prop.
  const [stitched, setStitched] = useState(null);
  const searchBox = useRef(null);
  const searchSeq = useRef(0); // doSearch generation — stale responses drop

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
      if (ev === "call-updated") {
        // An EXISTING row grew its response — a turn whose answer arrived in a
        // later OTLP batch, or a codex rollout answer stitched on seconds after
        // the prompt. Refetch, never prepend: the row is already in the feed,
        // and appending it again would double it. The store totals don't move
        // (no new row), so /api/stats is left alone.
        api.get("/api/feed").then(setCalls);
        setStitched((s) => ({ id: data.id, sessionId: data.sessionId, n: (s?.n ?? 0) + 1 }));
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
    // Generation counter: only the LATEST submission may render. Without it,
    // whichever POST resolves last wins — submit "foo" (slow) then "food"
    // (fast) and the late "foo" response would overwrite "food"'s results
    // under an input that still says "food". Clearing bumps it too, so a
    // late response can't resurrect a search the user already dismissed.
    const gen = ++searchSeq.current;
    if (!term) return setSearch(null);
    const r = await api.post("/api/search", { term });
    if (gen !== searchSeq.current) return; // superseded while in flight
    // Tolerate the store-missing shape (a bare []) — render it as no hits.
    setSearch({ term, hits: r?.hits ?? [], truncated: !!r?.truncated });
  }

  const visible = calls.filter((x) => !leaksOnly || x.hasLeak);
  // Server totals count the whole store; the feed state is only its newest
  // 500-row window. Fall back to the window while /api/stats is in flight.
  const callCount = stats?.calls ?? calls.length;
  const sessionCount = stats?.sessions ?? new Set(calls.map((x) => x.sessionId)).size;
  const agentCount = stats?.agents ?? new Set(calls.map((x) => x.agent).filter(Boolean)).size;
  // Demo events stay visible in every list, but an unbadged headline must
  // never present a drill as a real leak count.
  const realLeaks = leaks.filter((x) => !x.demo);
  // ONE derived view mode — the four main-area screens are mutually exclusive
  // by construction (a future view is one added case here, not a gate to
  // remember on every sibling). Search sits on top of whatever was open;
  // clearing it falls back to the state underneath, untouched.
  const view = search != null ? "search" : openSession != null ? "session" : tab;

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
          class=${(realLeaks.length ? "stat leak" : "stat leak zero") + " clickable"}
          title=${realLeaks.length
            ? "filter the feed to calls that leaked a secret"
            : "no real secrets detected (badged demo drills are excluded)"}
          onClick=${() => { setSearch(null); setOpenSession(null); setTab("calls"); setLeaksOnly(true); }}>
          <span class="leak-dot" aria-hidden="true"></span>
          <div class="stat-col">
            <span class="num">${realLeaks.length}</span>
            <span class="label">leak${realLeaks.length === 1 ? "" : "s"}</span>
          </div>
        </button>
        <button class="stat clickable" title="show every captured call"
          onClick=${() => { setSearch(null); setOpenSession(null); setLeaksOnly(false); setTab("calls"); }}>
          <span class="num">${callCount}</span>
          <span class="label">call${callCount === 1 ? "" : "s"}</span>
        </button>
        <button class="stat clickable" title="browse sessions"
          onClick=${() => { setSearch(null); setOpenSession(null); setTab("sessions"); }}>
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
            aria-label="search everything your agents sent"
            title="literal search over everything SENT — prompts and tool inputs, not model replies. Exact text, not fuzzy." />
        </form>
        <button class=${leaksOnly ? "toggle active" : "toggle"}
          aria-pressed=${leaksOnly ? "true" : "false"}
          onClick=${() => setLeaksOnly(!leaksOnly)}>
          <span class="toggle-dot" aria-hidden="true"></span>leaks only
        </button>
      </div>
    </header>
    <nav class="tabs" role="tablist">
      <!-- selection derives from the view mode, so an active SEARCH deselects
           both tabs — a screen reader must never hear "calls, selected" while
           the search results have replaced the calls list -->
      <button role="tab" aria-selected=${view === "calls" ? "true" : "false"}
        class=${view === "calls" ? "tab active" : "tab"}
        onClick=${() => { setSearch(null); setTab("calls"); setOpenSession(null); }}>calls</button>
      <button role="tab" aria-selected=${view === "sessions" || view === "session" ? "true" : "false"}
        class=${view === "sessions" || view === "session" ? "tab active" : "tab"}
        onClick=${() => { setSearch(null); setTab("sessions"); setOpenSession(null); }}>sessions${
          sessionCount > 0 ? html` <span class="tab-count">${sessionCount}</span>` : ""
        }</button>
    </nav>
    <main>
      ${banner &&
      html`<div class="banner" onClick=${() => setBanner(null)}>
        ▲ ${banner.title}${banner.subtitle ? ` — ${banner.subtitle}` : ""} — ${banner.body}
      </div>`}
      ${view === "search" && html`<${SearchView} search=${search} leaksOnly=${leaksOnly}
        onClear=${() => setSearch(null)}
        onSession=${(sid) => { setSearch(null); setOpenSession({ id: sid, row: null }); }} />`}
      ${view === "session" &&
      html`<${SessionTranscript} sessionId=${openSession.id} row=${openSession.row}
        refresh=${stitched?.sessionId === openSession.id ? stitched.n : 0}
        onBack=${() => setOpenSession(null)}
        onPurged=${() => {
          setOpenSession(null); // the session is gone — leave the transcript
          api.get("/api/feed").then(setCalls);
          api.get("/api/leaks").then(setLeaks);
          api.get("/api/stats").then(setStats);
        }} />`}
      ${view === "sessions" &&
      html`<${Sessions} leaksOnly=${leaksOnly}
        onOpen=${(s) => setOpenSession({ id: s.sessionId, row: s })} />`}
      ${view === "calls" && html`
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
          <span class="summary">what happened</span>
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
              refresh=${stitched?.id === x.id ? stitched.n : 0}
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

// Split a summary into display runs so the feed can mute the SENT half — the
// row reads two-toned in wire order: sent quiet, got-back bright. Recognizes
// exactly the shapes buildSummary emits, leading `"ask" → ` / `N x results → `
// (plus the legacy trailing suffix on old rows); anything else renders as one
// plain run. Text nodes only either way (§6.8).
function summaryParts(summary) {
  const s = summary ?? "(no summary)";
  // The ask bounds at 200, not firstLine's 40 — a placeholder straddling that
  // cap is run past whole, so the ask can reach 167 (see firstLine in daemon.ts).
  let m = s.match(/^("[^"]{1,200}" → |\d+ [A-Za-z_][\w.-]{0,40} results? → )([\s\S]*)$/);
  if (m) return [[m[1], true], [m[2], false]];
  m = s.match(/^([\s\S]*)( — (?:to "[^"]{0,80}"|after \d+ [A-Za-z_][\w.-]{0,40} results?))$/);
  return m ? [[m[1], false], [m[2], true]] : [[s, false]];
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
      <span class="model${x.model ? "" : " none"}">${x.model || "none"}</span>
      <span class="summary">${summaryParts(x.summary).map(([text, muted], i) =>
        muted ? html`<span key=${i} class="sum-suffix">${text}</span>` : text)}</span>
      ${x.hasLeak && html`<span class="chip leak">leak</span>`}
      ${x.demo && html`<span class="chip">[demo]</span>`}
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
            ${s.demo && html`<span class="chip">[demo]</span>`}
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
  // Summaries read in wire order: `"ask" → got` / `N x results → got`. For a
  // title, the ASK is the best material (it names the conversation, the way
  // chat apps title threads); a results-led line titles by what came back.
  // Older rows may still carry the legacy trailing suffix (— to "…" /
  // — after N x results) — strip it (rightmost, bounded). A summary matching
  // none of these is already title-shaped.
  let t = (raw ?? "").trim();
  // 200, not firstLine's 40 — see summaryParts above.
  let m = t.match(/^"([^"]{1,200})" → [\s\S]*$/);
  if (m) t = m[1];
  else if ((m = t.match(/^\d+ [A-Za-z_][\w.-]{0,40} results? → ([\s\S]*)$/))) t = m[1];
  else t = t.replace(/^([\s\S]*) — (?:to "[^"]{0,80}"|after \d+ [A-Za-z_][\w.-]{0,40} results?)$/, "$1");
  t = t.trim();
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
// `refresh` changes when a turn in THIS session gained its answer in place
// (see the call-updated frame): reload so the thread shows the response
// instead of sitting on the question until the next unrelated call.
function SessionTranscript({ sessionId, row, refresh, onBack, onPurged }) {
  const [view, setView] = useState(null);
  const [openCall, setOpenCall] = useState(null);
  const [confirmDel, setConfirmDel] = useState(false);
  const [deleting, setDeleting] = useState(false);
  useEffect(() => { api.get(`/api/session/${sessionId}`).then(setView); }, [sessionId, refresh]);

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
    // Same typing guard as the search view: Esc in the header's search input
    // clears the input (the browser's own behavior), not the whole transcript.
    const onKey = (e) => { if (e.key === "Escape" && !isTypingTarget(e)) onBack(); };
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
        ${view.demo && html`<span class="chip">[demo]</span>`}
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
              ${open && html`<${Detail} id=${t.id} refresh=${refresh} />`}
              ${t.messages.length > 0 &&
              html`<div class="dir-label sent"
                title=${t.source === "wire"
                  ? "what this turn's request sent to the provider (resent context is folded)"
                  : "what the agent reported sending this turn"}>⇢ request</div>`}
              ${t.messages.map(
                (m, j) => html`<${TMsg} key=${`${t.id}:${j}`} m=${m} leaks=${t.leaks} />`,
              )}
              ${((t.responseText != null && t.responseText !== "") || (t.responseCalls ?? []).length > 0) &&
              html`<div class="dir-label recv"
                title=${t.source === "wire"
                  ? "what the model sent back — its reply and/or the tools it asked the agent to run"
                  : "what the agent reported receiving back"}>⇠ response</div>`}
              ${t.responseText != null && t.responseText !== "" &&
              html`<${TMsg} key=${`${t.id}:resp`} leaks=${respLeaks(t)}
                m=${{ role: "response", content: t.responseText, sourceId: t.responseSourceId }} />`}
              ${(t.responseCalls ?? []).length > 0 &&
              html`<${ResponseCalls} calls=${t.responseCalls} leaks=${respLeaks(t)} />`}
              ${i === turns.length - 1 && !view.truncated && (t.responseCalls ?? []).length > 0 &&
              html`<div class="turn-note">results not captured yet (session ended or still running)</div>`}
              ${leakNotVisible(t) &&
              html`<div class="turn-note warn">a detected secret is not visible in the readable cards — open ▸ details → raw (for a reconstructed tool card, its own ▸ call detail)</div>`}
              ${t.messages.length === 0 && !t.responseText && (t.responseCalls ?? []).length === 0 &&
              html`<div class="turn-empty">(no parsed content — open details for raw bytes)</div>`}
            </div>
          `;
        })}
      </div>
    </div>
  `;
}

// The response section highlights with this turn's leaks PLUS the next
// turn's (responseLeaks): a secret inside the response's content is only
// scanned when it rides the next request, but it's DISPLAYED here first.
function respLeaks(t) {
  const extra = t.responseLeaks ?? [];
  return extra.length ? [...t.leaks, ...extra] : t.leaks;
}

// R7 backstop note: the turn is flagged but SOME detected value appears in
// none of its renderable text (secret in an HTTP header / protocol field /
// escaped form) — say where to look instead of showing a flag with nothing
// marked. Per-value, not all-or-nothing: one visible secret must not silence
// the pointer for a second, invisible one.
// Detail lines count as renderable: ToolCard puts m.detail / c.detail in the
// card header, and a derived-only redaction can leave its placeholder — which
// is the l.value searched for here — in a detail and nowhere else (the server's
// storedText makes the same call). Omitting them pointed the user at a raw
// pane that shows no more of that value than the header already does.
function leakNotVisible(t) {
  if (t.leaks.length === 0) return false;
  const text = [
    ...t.messages.flatMap((m) => [String(m.content ?? ""), String(m.detail ?? "")]),
    t.responseText ?? "",
    ...(t.responseCalls ?? []).flatMap((c) => [c.args ?? "", c.detail ?? ""]),
  ].join("\n");
  return t.leaks.some((l) => l.value && !text.includes(l.value));
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
function TMsg({ m, leaks, find }) {
  const [showSource, setShowSource] = useState(false);
  const content = typeof m.content === "string" ? m.content : JSON.stringify(m.content, null, 2);
  // The one unacceptable failure is a hidden secret: a leak-bearing message
  // never clamps and never renders collapsed.
  const hasLeak = (leaks ?? []).some((l) => l.value && content.includes(l.value));
  if (m.role === "tool" || m.role === "request") {
    return html`<${ToolCard} role=${m.role} content=${content} leaks=${leaks} hasLeak=${hasLeak}
      tool=${m.tool} kind=${m.kind} detail=${m.detail} sourceId=${m.sourceId} find=${find} />`;
  }
  // user / response / assistant-history / any future role: same card shell.
  // The turn's ⇢ request / ⇠ response group labels already carry direction, so
  // the two COMMON roles render bare (a plain card under "request" IS the
  // user's text; under "response" IS the model's reply) — repeating the word
  // would just be noise. Rare roles (assistant history after a compaction,
  // legacy "unknown") keep their header: a bare card must always mean the
  // group's obvious role, never something surprising.
  const bare = m.role === "user" || m.role === "response";
  return html`
    <div class=${hasLeak ? "mcard has-leak" : "mcard"}>
      ${(!bare || m.sourceId) && html`<div class="mc-head">
        ${!bare && html`<span class=${`mc-name ${m.role}`}>${m.role}</span>`}
        ${m.sourceId && html`<button class="chip"
          title="this response was captured on an earlier call — open that call's detail (raw bytes, sizes)"
          onClick=${() => setShowSource(!showSource)}>${showSource ? "▾" : "▸"} call</button>`}
      </div>`}
      <div class="mc-body">
        <${JsonBody} content=${content} leaks=${leaks}
          threshold=${m.role === "user" ? 1500 : 2500} hasLeak=${hasLeak} find=${find} />
      </div>
      ${showSource && html`<${Detail} id=${m.sourceId} />`}
    </div>
  `;
}

// A tool call / tool output (or a legacy "request" blob) in the same card
// shell as every other message: always-visible header (glyph, name, one-line
// preview), body only when opened, JSON pretty-printed for reading. Long cards
// start collapsed — unless they carry a secret, which forces them open.
// Enriched rows (parser-labeled tool/kind) get an explicit call vs result
// header; legacy rows keep the display-only "Name: payload" sniff, unchanged.
function ToolCard({ role, content, leaks, hasLeak, tool, kind, detail, hint, sourceId, find }) {
  // A card holding the searched term must not start collapsed — the user came
  // from search to see exactly that text (they can still fold it away).
  const startOpen = hasLeak || content.length <= 240 || hasFind(content, find);
  const [open, setOpen] = useState(startOpen);
  // A reconstructed subscription card keeps a path to the row it came from —
  // sequencing must never make captured bytes unreachable.
  const [showSource, setShowSource] = useState(false);
  const isRequest = role === "request";
  // Display-only parse of the "Name: payload" convention the mappers write.
  // Hostile content can at most mislabel its own card — never inject markup.
  const match = isRequest ? null : content.match(/^([A-Za-z_][\w.-]{0,40}):\s/);
  const name = isRequest
    ? "request"
    : kind === "result"
      ? `${tool ?? "tool"} result`
      : (tool ?? match?.[1] ?? "tool");
  // Strip the "Name: " prefix only when it IS the label we're showing: legacy
  // rows (the convention is all they have), or enriched CALL rows whose
  // convention content repeats the tool name. Enriched RESULTS never strip —
  // an output that merely LOOKS prefixed ("bash: command not found") is
  // genuine content and stays verbatim.
  const stripPrefix = match && (kind === undefined || (kind === "call" && match[1] === tool));
  const payload = stripPrefix ? content.slice(match[0].length) : content;
  const collapsible = !startOpen || hasLeak || content.length > 240;
  const glyph = isRequest ? "⇢" : kind === "result" ? "↳" : "⚙";
  const title = isRequest
    ? "what the agent reported sending — prompt and tool inputs as one block"
    : kind === "result" && detail
      ? `result of: ${detail}`
      : hint;
  return html`
    <div class=${hasLeak ? "mcard has-leak" : "mcard"} title=${title}>
      <div class=${collapsible ? "mc-head click" : "mc-head"}
        onClick=${() => collapsible && setOpen(!open)}>
        <span aria-hidden="true">${glyph}</span>
        <span class=${`mc-name ${isRequest ? "request" : "tool"}`}>${name}</span>
        ${kind && detail && html`<span class="mc-detail">${detail}</span>`}
        ${!open && html`<span class="mc-preview">${payload.slice(0, 200)}</span>`}
        ${hasLeak && html`<span class="chip leak">secret</span>`}
        ${sourceId &&
        html`<button class="chip" title="this card was captured as its own call — open that call's detail (raw bytes, sizes)"
          onClick=${(e) => { e.stopPropagation(); setShowSource(!showSource); }}>${showSource ? "▾" : "▸"} call</button>`}
        ${collapsible && html`<span class="mc-chev" aria-hidden="true">${open ? "▾" : "▸"}</span>`}
      </div>
      ${open &&
      html`<div class="mc-body scroll">
        <${JsonBody} content=${payload} leaks=${leaks} threshold=${1e9} hasLeak=${hasLeak} find=${find} />
      </div>`}
      ${showSource && html`<${Detail} id=${sourceId} />`}
    </div>
  `;
}

// The response side of a turn beyond its text: the tool calls the model asked
// for. Display-only — response bytes are not request-scanned (leak values come
// from the NEXT request, where this content is scanned; passed via leaks).
function ResponseCalls({ calls, leaks, find }) {
  return calls.map((c, i) => html`<${ToolCard} key=${i} role="tool" kind="call"
    tool=${c.tool} detail=${c.detail} content=${c.args ?? c.detail ?? c.tool}
    sourceId=${c.sourceId}
    leaks=${leaks} hasLeak=${(leaks ?? []).some((l) => l.value && String(c.args ?? "").includes(l.value))}
    find=${find}
    hint="tool call from the model's response — displayed, not scanned (Beagle scans requests)" />`);
}

// "3 min", "2 h" — how long a session's activity spans, for the sessions list.
function spanLabel(first, last) {
  const s = Math.round((last - first) / 1000);
  if (s < 60) return s > 1 ? `${s} s` : "";
  if (s < 3600) return `${Math.round(s / 60)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

// `refresh` bumps when this call gained a response in place — an open detail
// pane is the view that shows the response body, so it reloads too. `find` is
// the searched term when this pane was opened from the search view: every body
// marks it amber, and folds that would hide it start open.
function Detail({ id, refresh, onSession, find }) {
  const [detail, setDetail] = useState(null);
  const [raw, setRaw] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  useEffect(() => { api.get(`/api/call/${id}`).then(setDetail); }, [id, refresh]);
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
    : detail.source === "otel" && !detail.requestStructured && detail.requestRaw
      ? [{ role: "request", content: detail.requestRaw }]
      : [];
  const system = detail.system;
  const leaks = detail.leaks ?? [];
  const responseCalls = detail.responseCalls ?? [];
  const claudeToolCapture = detail.source === "otel" &&
    detail.endpoint?.startsWith("otel:tool_output:");
  // The server diffed this request against the previous call in the session:
  // newFrom marks where NEW content starts. null → no truthful claim (first
  // call, rewritten history, Mode B) → fall back to the naive last-message
  // split with no context/new labeling.
  const newFrom = detail.newFrom;
  const context = newFrom != null ? messages.slice(0, newFrom) : messages.slice(0, -1);
  const fresh = newFrom != null ? messages.slice(newFrom) : messages.slice(-1);
  // A context message that holds a leak must never sit behind the collapsed
  // fold — R7: detected secrets are ALWAYS visibly highlighted. When one does,
  // show the whole history inline (correctness beats brevity here). `detail`
  // counts as much as `content`: a derived-only redaction can leave its
  // placeholder in a card's detail line and nowhere else (see storedText in
  // detail.ts) — every sibling surface (findInOlder, readableText,
  // leakNotVisible) already scans both, and a folded card renders NEITHER.
  // The searched term earns the same treatment: a search hit whose match sits
  // in resent context must not open onto a view with the match folded away.
  const leakInOlder = context.some((m) =>
    leaks.some((l) =>
      l.value && (String(m.content ?? "").includes(l.value) || String(m.detail ?? "").includes(l.value))),
  );
  const findInOlder = find != null && context.some(
    (m) => hasFind(String(m.content ?? ""), find) || hasFind(String(m.detail ?? ""), find),
  );
  const showOlderInline = (newFrom == null && context.length <= 3) || leakInOlder || findInOlder;
  // Nothing structured on EITHER side → raw is the only honest view; don't
  // show an empty timeline with a toggle the user has to discover. A Claude
  // turn may legitimately have no request cards after its tool invocation is
  // placed on the response side, so response structure counts here too.
  const hasStructure = messages.length > 0 || system != null ||
    detail.responseText != null || responseCalls.length > 0;
  const showRaw = raw || !hasStructure;
  // What the readable view actually SHOWS inline: the messages (earlier ones
  // holding a leak are force-shown, above), each card's detail line (ToolCard
  // renders it in the header, and a derived-only redaction can leave its
  // placeholder there and nowhere else), the response text, and the response's
  // tool-call args. NOT the system prompt — it sits in a collapsed,
  // un-highlighted chip — and NOT anything only in an HTTP header or protocol
  // field. If the secret lives only in those, point the user at raw.
  const readableText = [
    ...messages.flatMap((m) => [m.content, m.detail ?? ""]),
    detail.responseText ?? "",
    ...responseCalls.flatMap((c) => [c.args ?? "", c.detail ?? ""]),
  ].join("\n");
  // Per-value, not all-or-nothing (mirrors leakNotVisible): if ANY detected
  // value is absent from the readable text, point at raw — one visible secret
  // must not suppress the pointer for a second that lives only in the system
  // prompt / a header / a protocol field.
  const leakHiddenInRaw = leaks.length > 0 && !showRaw && leaks.some((l) => l.value && !readableText.includes(l.value));
  // Response-section highlighting: this call's leaks plus the NEXT request's
  // (where the response's content actually got scanned).
  const respHighlights = (detail.responseLeaks ?? []).length
    ? [...leaks, ...detail.responseLeaks]
    : leaks;

  return html`
    <div class="detail">
      <div class="meta">
        <div class="meta-primary">
          <span class="agent-name">${detail.agent ?? "?"}</span>
          ${detail.demo && html`<span class="chip">[demo]</span>`}
          <span class="arrow" aria-hidden="true">→</span>
          <span class="to">${detail.provider ?? "?"}${detail.model ? " · " + detail.model : " · no model"}</span>
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
        🔴 ${leaks.length} secret${leaks.length === 1 ? "" : "s"} sent in this call —${" "}
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
          ? "the stored request and response text, without readable projection"
          : "the stored scan text derived from the agent's report"}</span>`}
      </div>`}
      ${showRaw
        ? claudeToolCapture
          ? html`
              <div class="dir-label sent">captured tool name + input + result</div>
              <${RawBody} body=${detail.requestRaw} leaks=${leaks} find=${find} />
            `
          : html`
              <div class="dir-label sent">⇢ request</div>
              <${RawBody} body=${detail.requestRaw} leaks=${leaks} find=${find} />
              <div class="dir-label recv">⇠ response</div>
              <${RawBody} body=${detail.responseRaw} leaks=${leaks} find=${find} />
              ${detail.sseRaw &&
              html`<h4>raw stream (as received)</h4><pre>${detail.sseRaw}</pre>`}
            `
        : html`
            ${system != null &&
            html`<${Chip} label="system prompt" body=${system} find=${find} />`}
            ${messages.length > 0 &&
            html`<div class="dir-label sent"
              title=${detail.source === "wire"
                ? "what this request sent to the provider — earlier messages fold below"
                : "what the agent reported sending"}>⇢ request</div>`}
            ${context.length > 0 && showOlderInline
              ? context.map((m) => html`<${TMsg} m=${m} leaks=${leaks} find=${find} />`)
              : html`
                  ${context.length > (newFrom != null ? 0 : 3) &&
                  html`<div class="folded history-fold" onClick=${() => setHistoryOpen(!historyOpen)}>
                    ${historyOpen ? "▾ hide" : "▸ show"} ${newFrom != null
                      ? `context — ${context.length} earlier message${context.length === 1 ? "" : "s"} (resent with every request)`
                      : `the ${context.length} earlier messages`}
                  </div>`}
                  ${historyOpen && context.map((m) => html`<${TMsg} m=${m} leaks=${leaks} find=${find} />`)}
                `}
            ${fresh.map((m) => html`<${TMsg} m=${m} leaks=${leaks} find=${find} />`)}
            ${(detail.responseText != null || responseCalls.length > 0) &&
            html`<div class="dir-label recv"
              title=${detail.source === "wire"
                ? "what the model sent back — its reply and/or the tools it asked the agent to run"
                : "what the agent reported receiving back"}>⇠ response</div>`}
            ${detail.responseText != null &&
            html`<${TMsg} m=${{ role: "response", content: detail.responseText }} leaks=${respHighlights} find=${find} />`}
            ${responseCalls.length > 0 &&
            html`<${ResponseCalls} calls=${responseCalls} leaks=${respHighlights} find=${find} />`}
          `}
    </div>
  `;
}

// Same collapsible card the transcript uses for its system prompt — one
// visual for one concept, on both screens. The system prompt IS indexed for
// search, so a hit can live only here: when it does, the chip starts open and
// the term is amber-marked (leak marking stays out of this card by design —
// the leakbar's "open raw" pointer owns that case; Highlighted with no leaks
// renders text nodes + find marks only).
function Chip({ label, body, find }) {
  const [open, setOpen] = useState(() => hasFind(body, find));
  return html`
    <div class="syscard">
      <div class="sys-head" onClick=${() => setOpen(!open)}>${open ? "▾" : "▸"} ${label}</div>
      ${open && html`<pre><${Highlighted} text=${body} find=${find} /></pre>`}
    </div>
  `;
}

// One context snippet, rendered as ONE Highlighted pass over the whole window
// (pre + match + post joined back together). One pass, not three: a detected
// secret can STRADDLE the match boundary — searching a prefix of your own
// leaked key is the flagship use — and a value split across segments would
// slip past each segment's whole-value check, rendering a secret without its
// red mark. Joined, the leak split runs first and wins whole; the term's own
// occurrences (the central match included — it is a verbatim slice of this
// text) get the amber find mark from the same pass. Same two invariants as
// every body (§6.8 text nodes, R7 marks); the server's window widening keeps
// values whole at the window's outer edges. Known residual: a term whose own
// text was altered by whitespace collapse loses its amber (the header still
// names it); red leak marks are unaffected.
function Snippet({ s, leaks, term }) {
  return html`<div class="sv-snippet">
    <${Highlighted} text=${s.pre + s.match + s.post} leaks=${leaks} find=${term} />
  </div>`;
}

// One search hit: a meta line (when, what the turn did), the snippet showing
// WHERE the term appeared, and — on click — the call's full detail opening
// INLINE right below, with the term marked throughout. The old design jumped
// to the calls tab and expanded a row somewhere down the feed (or nowhere at
// all, when the call was older than the feed window); this one answers "where
// did my click go?" by never leaving the spot the user clicked.
function SearchHit({ h, term, open, onToggle, onSession }) {
  return html`
    <div class=${h.hasLeak ? "sv-hit leak" : "sv-hit"}>
      <div class="sv-hitrow" onClick=${onToggle}
        title=${open ? "hide this call's detail" : "show this call's full detail right here"}>
        <span class=${h.hasLeak ? "dot err" : "dot"}></span>
        <span class="sv-time">${fmtDivider(h.tsRequest, true)}</span>
        <span class="sv-sum" title=${h.summary ?? ""}>${h.summary ?? "(no summary)"}</span>
        ${h.matchCount > 1 && html`<span class="chip"
          title=${"the term occurs " + h.matchCount + " times in this call's sent text — " +
            "the snippets window the first few; open the call to see every occurrence marked"}>${h.matchCount} matches</span>`}
        ${h.hasLeak && html`<span class="chip leak">leak</span>`}
        ${h.demo && html`<span class="chip">[demo]</span>`}
        <button class="linklike sv-toggle"
          onClick=${(e) => { e.stopPropagation(); onToggle(); }}>
          ${open ? "▾ hide call" : "▸ show call"}</button>
      </div>
      ${h.snippets.slice(0, open ? h.snippets.length : 1).map(
        (s, i) => html`<${Snippet} key=${i} s=${s} leaks=${h.leaks} term=${term} />`,
      )}
      ${open && html`<${Detail} id=${h.callId} find=${term} onSession=${onSession} />`}
    </div>
  `;
}

// The search view — a first-class screen that REPLACES the list while active
// (results and feed no longer interleave). Hits group by session, newest
// session first, conversation order inside; Esc or ✕ returns to the view the
// user was on, and the header input still holds the term for a re-run. The
// header's "leaks only" toggle narrows THIS list too, the same way it narrows
// the feed and the sessions tab — a control that visibly reacts must never be
// a silent no-op on the screen it's shown beside.
function SearchView({ search, leaksOnly, onClear, onSession }) {
  const { term, hits, truncated } = search;
  const [openHit, setOpenHit] = useState(null);
  useEffect(() => { setOpenHit(null); }, [search]); // new results → no stale open pane
  useEffect(() => {
    // Esc backs out of the results — but while the user is typing in a field
    // (the search input above), the browser's own Escape (clear the text)
    // must win alone, not also tear down the view they're refining.
    const onKey = (e) => { if (e.key === "Escape" && !isTypingTarget(e)) onClear(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClear]);

  // Group by session: groups keep arrival order (newest-first — a Map holds
  // insertion order), hits inside flip to chronological so a conversation
  // reads down. Memoized: the App re-renders on every SSE frame, and
  // regrouping an unchanged result set each time is avoidable churn.
  const { shown, groups } = useMemo(() => {
    const kept = leaksOnly ? hits.filter((h) => h.hasLeak) : hits;
    const bySession = new Map();
    for (const h of kept) {
      let g = bySession.get(h.sessionId);
      if (!g) {
        g = { sessionId: h.sessionId, agent: h.agent, demo: h.demo, hits: [] };
        bySession.set(h.sessionId, g);
      }
      g.hits.push(h);
    }
    const gs = [...bySession.values()];
    for (const g of gs) g.hits.reverse();
    return { shown: kept, groups: gs };
  }, [search, leaksOnly]);
  const hidden = hits.length - shown.length;

  // The plural stays open-ended ("1+ calls") whenever the server page was cut:
  // with "leaks only" narrowing a truncated page, even a single shown call
  // can't claim to be the only one.
  const plus = truncated ? "+" : "";
  const headline = `sent in ${shown.length}${plus} ${shown.length === 1 && !plus ? "call" : "calls"}` +
    ` across ${groups.length}${plus} ${groups.length === 1 && !plus ? "session" : "sessions"}`;

  return html`
    <div class="searchview" role="region" aria-label="search results">
      <div class="sv-head">
        <span class="sv-q">“${term}”</span>
        ${shown.length > 0
          ? html`<span class="sv-count" aria-live="polite">${headline}</span>`
          : hits.length === 0
            ? html`<span class="sv-count" aria-live="polite">no matches — not in any call still in the store.</span>`
            : html`<span class="sv-count" aria-live="polite">all ${hits.length}${plus} matching
                call${hits.length === 1 ? "" : "s"} hidden by leaks only</span>`}
        <button onClick=${onClear} title="back to where you were (Esc)">✕ clear</button>
      </div>
      ${truncated &&
      html`<div class="sv-note">showing only the ${hits.length} newest matching calls — narrow the term to reach older ones</div>`}
      ${hidden > 0 && shown.length > 0 &&
      html`<div class="sv-note">leaks only — ${hidden} clean call${hidden === 1 ? "" : "s"} hidden</div>`}
      ${hits.length === 0 &&
      html`<div class="empty">
        search covers what your agents <span class="hl">sent</span>${" "}
        — prompts and tool inputs, exact text — not what models replied.<br />
        <span class="hint">purged or expired calls are no longer searchable; a match here${" "}
        is proof the text left the machine, absence is not proof it never did</span>
      </div>`}
      ${hits.length > 0 && shown.length === 0 &&
      html`<div class="empty">
        none of the matching calls leaked a secret — turn off${" "}
        <span class="hl">leaks only</span> to see all ${hits.length}${plus} of them.
      </div>`}
      ${groups.map(
        (g) => html`
          <div class="sv-group" key=${g.sessionId}>
            <div class="sv-ghead">
              <span class="s-agent">${g.agent ?? "?"}</span>
              ${g.demo && html`<span class="chip">[demo]</span>`}
              <span aria-hidden="true">·</span>
              <span>session</span>
              <${CopyChip} value=${g.sessionId} />
              <span aria-hidden="true">·</span>
              <span>${g.hits.length} call${g.hits.length === 1 ? "" : "s"} matched</span>
              <button class="linklike sv-gopen" onClick=${() => onSession(g.sessionId)}
                title="read this whole session as a conversation">view session ›</button>
            </div>
            ${g.hits.map(
              (h) => html`<${SearchHit} key=${h.callId} h=${h} term=${term}
                open=${openHit === h.callId}
                onToggle=${() => setOpenHit(openHit === h.callId ? null : h.callId)}
                onSession=${onSession} />`,
            )}
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
bootstrap().catch(() => false).then((ok) => {
  const root = document.getElementById("app");
  if (!ok) {
    // Reached for every non-success: a used/absent link, a rejected credential,
    // OR the viewer no longer running (fetch rejected). `beagle ui` is the fix
    // for all of them, so keep the copy accurate rather than only naming the
    // used-link case. The .catch above guarantees this renders instead of a
    // blank page even if bootstrap throws unexpectedly.
    render(
      html`<div class="empty">
        This viewer session is no longer active — the one-time link was already used,
        or the viewer has stopped.<br />
        Run <code>beagle ui</code> to open a fresh dashboard.
      </div>`,
      root,
    );
    return;
  }
  render(html`<${App} />`, root);
});
