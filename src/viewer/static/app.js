// Beagle dashboard (Preact + htm, buildless — what ships is what's in the
// repo). Rendering rule: captured content is ALWAYS text nodes; nothing from
// the store is ever interpolated into markup (design §6.8).
import { h, render } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import htm from "htm";

const html = htm.bind(h);

// ---- session bootstrap: exchange the one-time URL token for a header credential ----
let credential = null;

async function bootstrap() {
  const params = new URLSearchParams(location.search);
  const boot = params.get("boot");
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
  const [exchanges, setExchanges] = useState([]);
  const [leaks, setLeaks] = useState([]);
  const [leaksOnly, setLeaksOnly] = useState(false);
  const [sessionFilter, setSessionFilter] = useState(null);
  const [searchHits, setSearchHits] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [banner, setBanner] = useState(null);
  const [expanded, setExpanded] = useState(null);
  const searchBox = useRef(null);

  useEffect(() => {
    api.get("/api/feed").then(setExchanges);
    api.get("/api/leaks").then(setLeaks);
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
      if (ev === "exchange") setExchanges((xs) => [data, ...xs]);
      if (ev === "alert") {
        setBanner(data);
        api.get("/api/leaks").then(setLeaks);
        api.get("/api/feed").then(setExchanges);
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

  const visible = exchanges.filter(
    (x) => (!leaksOnly || x.hasLeak) && (!sessionFilter || x.sessionId === sessionFilter),
  );

  return html`
    <header>
      <h1>🐕 beagle</h1>
      <span class=${leaks.length ? "leak-counter" : "leak-counter zero"}>
        ${leaks.length} leak${leaks.length === 1 ? "" : "s"}
      </span>
      <div class="controls">
        <form onSubmit=${doSearch}>
          <input ref=${searchBox} type="search" placeholder="was this ever sent? (literal search)" />
        </form>
        <button class=${leaksOnly ? "active" : ""} onClick=${() => setLeaksOnly(!leaksOnly)}>
          leaks only
        </button>
        ${sessionFilter &&
        html`<button class="active" onClick=${() => setSessionFilter(null)}>
          session ${sessionFilter.slice(0, 8)} ✕
        </button>`}
      </div>
    </header>
    <main>
      ${banner &&
      html`<div class="banner" onClick=${() => setBanner(null)}>
        ▲ ${banner.title} — ${banner.body}
      </div>`}
      ${searchHits !== null && html`<${SearchResults} hits=${searchHits} term=${searchTerm}
        onClear=${() => setSearchHits(null)} onOpen=${(id) => setExpanded(id)} />`}
      ${visible.length === 0 && html`<div class="empty">
        no calls${leaksOnly ? " with leaks" : ""} yet — run an agent under
        ${" "}<code>beagle run</code> and its traffic appears here live
      </div>`}
      ${visible.map(
        (x) => html`
          <${Row} key=${x.id} x=${x}
            onToggle=${() => setExpanded(expanded === x.id ? null : x.id)}
            onSession=${() => setSessionFilter(x.sessionId)} />
          ${expanded === x.id && html`<${Detail} id=${x.id} />`}
        `,
      )}
    </main>
    <footer>
      local only · outbound connections: only your model providers · telemetry: none ·
      viewer: on while this tab is open (loopback, tokened) · captures shown from your local store
    </footer>
  `;
}

function Row({ x, onToggle, onSession }) {
  const t = new Date(x.tsRequest).toLocaleTimeString();
  const kb = x.bytesReq ? (x.bytesReq / 1024).toFixed(1) + " KB" : "";
  const tok = x.tokensOut != null ? `${x.tokensIn ?? "?"}→${x.tokensOut}` : "";
  return html`
    <div class=${x.hasLeak ? "row leak" : "row"} onClick=${onToggle}>
      <span class=${x.status && x.status >= 400 ? "dot err" : "dot"}></span>
      <span class="time">${t}</span>
      <span class="agent">${x.agent ?? "?"}</span>
      <span class="model">${x.model ?? ""}</span>
      <span class="summary">${x.summary ?? "(no summary)"}</span>
      ${x.hasLeak && html`<span class="chip leak">leak</span>`}
      ${x.source === "wire"
        ? html`<span class="chip wire" title="wire-verified — observed on the wire">✓ wire</span>`
        : html`<span class="chip otel" title="agent-reported — the agent's own self-report">agent</span>`}
      ${x.scanState !== "ok" && html`<span class="chip">scan incomplete</span>`}
      <span class="weight">${kb} ${tok}</span>
      <span class="chip" onClick=${(e) => { e.stopPropagation(); onSession(); }}>
        s:${x.sessionId.slice(0, 6)}
      </span>
    </div>
  `;
}

function Detail({ id }) {
  const [detail, setDetail] = useState(null);
  const [raw, setRaw] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  useEffect(() => { api.get(`/api/exchange/${id}`).then(setDetail); }, [id]);
  if (!detail) return html`<div class="detail">loading…</div>`;
  if (detail.error) return html`<div class="detail">${detail.error}</div>`;

  // The server assembles the readable structure (detail.ts): parsed messages,
  // reassembled response text, and the secret strings to highlight.
  const messages = detail.messages ?? [];
  const system = detail.system;
  const leaks = detail.leaks ?? [];
  const older = messages.slice(0, -1);
  const newest = messages.slice(-1);
  // Nothing structured → raw is the only honest view; don't show an empty
  // timeline with a toggle the user has to discover.
  const hasStructure = messages.length > 0 || system != null;
  const showRaw = raw || !hasStructure;

  return html`
    <div class="detail">
      <div class="meta">
        <div><span class="k">call</span> ${detail.id}</div>
        <div>
          <span class="k">from</span> ${detail.agent}${" "}
          <span class="k">to</span> ${detail.provider}${detail.model ? " / " + detail.model : ""}
        </div>
        <div>
          <span class="k">session</span> ${detail.sessionId.slice(0, 8)} ·${" "}
          <span class="k">grouped by</span> ${groupedBy(detail.sessionTier)}
        </div>
        ${detail.captureState !== "ok" &&
        html`<div class="warn">⚠ capture truncated — the stored bytes are incomplete</div>`}
        ${detail.scanState !== "ok" &&
        html`<div class="warn">⚠ scan incomplete — this body was not fully verified, not marked clean</div>`}
      </div>
      ${leaks.length > 0 &&
      html`<div class="leakbar">
        🔴 ${leaks.length} secret${leaks.length === 1 ? "" : "s"} sent in this call —
        highlighted below:
        ${leaks.map((l) => html`<span class="chip leak">${l.secretType}</span>`)}
      </div>`}
      ${hasStructure &&
      html`<button class=${showRaw ? "active" : ""} onClick=${() => setRaw(!raw)}>
        ${showRaw ? "structured view" : "raw bytes"}
      </button>`}
      ${showRaw
        ? html`
            <h4>request</h4>
            <pre><${Highlighted} text=${pretty(detail.requestRaw)} leaks=${leaks} /></pre>
            <h4>response</h4>
            <pre>${pretty(detail.responseRaw)}</pre>
            ${detail.sseRaw &&
            html`<h4>raw stream (as received)</h4><pre>${detail.sseRaw}</pre>`}
          `
        : html`
            ${system != null &&
            html`<${Chip} label=${`system · ${system.length} chars`} body=${system} />`}
            ${older.length > 0 &&
            html`<div class="folded" onClick=${() => setHistoryOpen(!historyOpen)}>
              ${historyOpen ? "▾" : "▸"} ${older.length} earlier message${older.length === 1 ? "" : "s"}
            </div>`}
            ${historyOpen && older.map((m) => html`<${Msg} m=${m} leaks=${leaks} />`)}
            ${newest.map((m) => html`<${Msg} m=${m} leaks=${leaks} />`)}
            ${detail.responseText != null &&
            html`<${Msg} m=${{ role: "assistant", content: detail.responseText }} leaks=${leaks} />`}
          `}
    </div>
  `;
}

// Renders text, wrapping each detected secret value in a red <mark>. Splits on
// values and builds text nodes only — never raw-HTML injection (§6.8).
function Highlighted({ text, leaks }) {
  if (!leaks || leaks.length === 0 || typeof text !== "string") return text ?? "";
  // Longest-first so that when two values share a start (one a prefix of the
  // other, e.g. a password nested in a connection string) the longer wins and
  // the highlight isn't fragmented.
  const values = [...new Set(leaks.map((l) => l.value).filter(Boolean))].sort(
    (a, b) => b.length - a.length,
  );
  const out = [];
  let rest = text;
  let guard = 0;
  while (rest && guard++ < 100000) {
    let at = -1;
    let hit = null;
    for (const v of values) {
      const i = rest.indexOf(v);
      // strict <: at an equal position the earlier (longer) value already won
      if (i !== -1 && (at === -1 || i < at)) { at = i; hit = v; }
    }
    if (at === -1) { out.push(rest); break; }
    if (at > 0) out.push(rest.slice(0, at));
    out.push(html`<mark class="leak" title="detected secret">${hit}</mark>`);
    rest = rest.slice(at + hit.length);
  }
  return html`${out}`;
}

function Chip({ label, body }) {
  const [open, setOpen] = useState(false);
  return html`
    <div>
      <span class="chip" onClick=${() => setOpen(!open)}>${label} ${open ? "▾" : "▸"}</span>
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
      <div><${Highlighted} text=${content} leaks=${leaks} /></div>
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
            <a href="#" onClick=${(e) => { e.preventDefault(); onOpen(hit.exchangeId); }}>
              ${hit.exchangeId.slice(0, 8)}
            </a>
            ${" "}${new Date(hit.tsRequest).toLocaleString()} · session ${hit.sessionId.slice(0, 8)}
            · <mark>${term}</mark>
          </div>
        `,
      )}
    </div>
  `;
}

// Plain-language read of HOW this exchange was grouped into its session (the
// resolver's tier), with the confidence that grouping carries — so the label
// says what it means, not an internal tag like "conv-id".
function groupedBy(tier) {
  switch (tier) {
    case "conv-id": return "the provider's conversation id (high confidence)";
    case "prefix": return "matching message history (high confidence)";
    case "compaction-link": return "history matched across a compaction (medium confidence)";
    case "run": return "the same run, no history match (lower confidence)";
    case "time-gap": return "recent activity — a best guess (low confidence)";
    default: return tier;
  }
}

function pretty(s) {
  if (!s) return "(empty)";
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}

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
