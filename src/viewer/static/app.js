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
        no exchanges${leaksOnly ? " with leaks" : ""} yet — run an agent under
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
      ${x.source === "otel" && html`<span class="chip otel">agent-reported</span>`}
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

  let messages = [];
  let system = null;
  try {
    const body = JSON.parse(detail.requestBody);
    system = typeof body.system === "string" ? body.system : null;
    // Anthropic uses `messages`; the Responses API uses `input` items.
    const items = Array.isArray(body.messages) ? body.messages : body.input;
    messages = Array.isArray(items) ? items : [];
  } catch { /* raw only */ }

  const older = messages.slice(0, -1);
  const newest = messages.slice(-1);
  // Nothing structured to show → raw is the only honest view; don't render
  // an empty timeline with a toggle the user has to discover.
  const hasStructure = messages.length > 0 || system !== null;
  const showRaw = raw || !hasStructure;

  return html`
    <div class="detail">
      <div class="meta">
        ${detail.id} · ${detail.agent} → ${detail.provider}${detail.model ? "/" + detail.model : ""}
        · session ${detail.sessionId.slice(0, 8)} (${detail.sessionTier})
        ${detail.captureState !== "ok" ? " · ⚠ capture truncated" : ""}
        ${detail.scanState !== "ok" ? " · ⚠ scan incomplete — unverified, not clean" : ""}
      </div>
      ${hasStructure &&
      html`<button class=${showRaw ? "active" : ""} onClick=${() => setRaw(!raw)}>
        ${showRaw ? "structured view" : "raw bytes"}
      </button>`}
      ${showRaw
        ? html`
            <h4>request</h4>
            <pre>${pretty(detail.requestBody)}</pre>
            <h4>response</h4>
            <pre>${pretty(detail.responseBody)}</pre>
          `
        : html`
            ${system !== null &&
            html`<${Chip} label=${`system · ${system.length} chars`} body=${system} />`}
            ${older.length > 0 &&
            html`<div class="folded" onClick=${() => setHistoryOpen(!historyOpen)}>
              ${historyOpen ? "▾" : "▸"} ${older.length} earlier message${older.length === 1 ? "" : "s"}
            </div>`}
            ${historyOpen && older.map((m) => html`<${Msg} m=${m} />`)}
            ${newest.map((m) => html`<${Msg} m=${m} />`)}
            ${detail.responseBody &&
            html`<${Msg} m=${{ role: "assistant", content: extractText(detail.responseBody) }} />`}
          `}
    </div>
  `;
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

function Msg({ m }) {
  const content =
    typeof m.content === "string" ? m.content : JSON.stringify(m.content, null, 2);
  return html`
    <div class=${"msg " + m.role}>
      <div class="role">${m.role}</div>
      <div>${content}</div>
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
              found in ${hits.length} exchange${hits.length === 1 ? "" : "s"} across
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

function pretty(s) {
  if (!s) return "(empty)";
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}

function extractText(responseBody) {
  try {
    const body = JSON.parse(responseBody);
    if (Array.isArray(body.content)) {
      return body.content.map((b) => b.text ?? "").join("");
    }
    if (body.choices?.[0]?.message?.content) return body.choices[0].message.content;
    return responseBody;
  } catch {
    return responseBody;
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
