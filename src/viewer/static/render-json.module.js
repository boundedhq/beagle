// Safe body rendering — the ONE place a captured body becomes DOM, so the whole
// §6.8 / R7 audit surface lives in a single file. Every function here holds two
// invariants: (§6.8) captured text is only ever interpolated as a text node,
// never markup; (R7) a detected secret is always visibly highlighted — no fold
// or clamp ever hides one. Everything that shows a stored body goes through
// JsonBody (readable), RawBody (raw), or Highlighted (search snippets — flat
// text that still owes both invariants); those are the only RENDER exports
// (rawCanFold, parseSegments, findRuns, and hasFind are also exported, but
// they are pure functions returning plain data — they never touch the DOM).
import { h } from "preact";
import { useMemo, useState } from "preact/hooks";
import htm from "htm";

const html = htm.bind(h);

// ASCII-only lowercase, length-preserving — matches the store's LIKE matching
// (which made the call a search hit), and keeps folded offsets valid on the
// original text (full Unicode folding can change length: "İ" → "i̇").
// Mirrors asciiLower in src/viewer/feed-query.ts: the server folds the same
// way to find and window matches, and a hit it flags must re-match HERE for
// the marks and fold-opens. Change both together, or a search hit opens with
// its match unmarked and folded away.
const asciiLower = (s) => s.replace(/[A-Z]/g, (c) => c.toLowerCase());

// Pure splitter behind the search-term marks: runs of text, hit or not, for a
// literal ASCII-case-insensitive term. Exported for tests (no DOM).
export function findRuns(text, find) {
  const whole = [{ text: text ?? "", hit: false }];
  if (!find || typeof text !== "string" || text === "") return whole;
  const hay = asciiLower(text);
  const needle = asciiLower(find);
  const runs = [];
  let pos = 0;
  for (let i = hay.indexOf(needle); i !== -1; i = hay.indexOf(needle, pos)) {
    if (i > pos) runs.push({ text: text.slice(pos, i), hit: false });
    runs.push({ text: text.slice(i, i + needle.length), hit: true });
    pos = i + needle.length;
  }
  if (runs.length === 0) return whole;
  if (pos < text.length) runs.push({ text: text.slice(pos), hit: false });
  return runs;
}

// Does the text contain the searched term at all? (Same fold as findRuns —
// used for "start this fold open" decisions, so a match is never hidden.)
export function hasFind(text, find) {
  if (!find || typeof text !== "string") return false;
  return asciiLower(text).includes(asciiLower(find));
}

// A text run with its search-term matches wrapped in an amber <mark> — text
// nodes only (§6.8). Display-only: never consulted for parse/fold decisions.
// One scan: findRuns already answers "no match" with a single plain run, so a
// hasFind pre-check would fold and scan the same text a second time for
// nothing (this runs per key, string leaf, and prose run of a searched body).
function findMarked(text, find) {
  if (!find || typeof text !== "string") return text;
  const runs = findRuns(text, find);
  if (runs.length === 1 && !runs[0].hit) return text;
  return runs.map((r) => (r.hit ? html`<mark class="find">${r.text}</mark>` : r.text));
}

// Renders text, wrapping each detected secret value in a red <mark>. Splits on
// values and builds text nodes only — never raw-HTML injection (§6.8). The
// searched term (find) gets an amber mark on the runs BETWEEN leak marks — a
// secret's red mark always wins whole, never fragmented by a search overlap.
// Exported for the search view's snippets, which render captured text outside
// a JsonBody and owe it the same two invariants.
export function Highlighted({ text, leaks, find }) {
  if (!leaks || leaks.length === 0 || typeof text !== "string")
    return typeof text === "string" ? html`${findMarked(text, find)}` : (text ?? "");
  // value → tier, so each mark is colored by confidence. The louder
  // "structured" tier wins if the same value was flagged under both.
  const tierOf = new Map();
  for (const l of leaks) {
    if (!l.value) continue;
    if (l.tier === "structured" || !tierOf.has(l.value)) tierOf.set(l.value, l.tier);
  }
  // Longest-first so that when two values share a start (one a prefix of the
  // other, e.g. a password nested in a connection string) the longer wins and
  // the highlight isn't fragmented.
  const values = [...tierOf.keys()].sort((a, b) => b.length - a.length);
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
    if (at === -1) { out.push(findMarked(rest, find)); break; }
    if (at > 0) out.push(findMarked(rest.slice(0, at), find));
    // Structured = red (loud, alerted); possible = amber (lower confidence,
    // logged but never alerted) — the distinction the user can't get otherwise.
    const possible = tierOf.get(hit) === "possible";
    out.push(html`<mark
      class=${possible ? "leak possible" : "leak"}
      title=${possible ? "possible secret — lower confidence, not alerted" : "detected secret"}
    >${hit}</mark>`);
    rest = rest.slice(at + hit.length);
  }
  return html`${out}`;
}

// The "Name: payload" convention the mappers write, sniffed display-only. The
// head cap is 80 — MCP tool names (mcp__openaiDeveloperDocssearch_openai_docs,
// 43 chars) overflow the old 40 and silently lost their fold/pretty-print.
const NAMED_HEAD = /^([A-Za-z_][\w.-]{0,80}):\s*([\s\S]*)$/;

// Pretty-print JSON for reading, applied to EVERY displayed body: each line
// that parses as a JSON object/array (bare, or behind a "Name: " prefix like
// the Mode B "Bash: {...}" convention) re-serializes with 2-space indent.
// Guard: if reformatting would lose an inline secret highlight (the value no
// longer substring-matches), that line stays verbatim — a leak never loses
// its red mark to cosmetics.
// Reached only when parseSegments declined the body (no JSON line, or a leak
// would not survive the split) — its per-line pretty-print is the gentler
// fallback for exactly those cases.
function prettyContent(text, leaks) {
  const values = (leaks ?? []).map((l) => l.value).filter(Boolean);
  const out = text
    .split("\n")
    .map((line) => {
      const t = line.trim();
      const named = t.match(NAMED_HEAD);
      const raw = named ? named[2] : t;
      if (!raw.startsWith("{") && !raw.startsWith("[")) return line;
      try {
        const p = JSON.stringify(JSON.parse(raw), null, 2);
        for (const v of values) if (line.includes(v) && !p.includes(v)) return line;
        return named ? `${named[1]}:\n${p}` : p;
      } catch {
        return line;
      }
    })
    .join("\n");
  // Whole-string backstop over the per-line guard: a secret that STRADDLES a
  // line boundary can be broken by reformatting even though each line's own
  // guard passed (per-line `includes` never saw the whole value). If any
  // detected value the input carried is no longer contiguous in the result,
  // return the text verbatim — a highlight is never worth losing to cosmetics.
  // This also ties hasLeak (computed on `text`) to the rendered output: the
  // result now contains a value iff `text` did.
  for (const v of values) if (text.includes(v) && !out.includes(v)) return text;
  return out;
}

// ---- foldable JSON tree ----------------------------------------------------
// Readable bodies that ARE one JSON document render as a devtools-style tree:
// objects/arrays fold, primitives read cleanly. §6.8 holds — every key and
// value is interpolated as a text node, never markup. R7 holds twice over:
// a subtree holding a detected secret starts expanded, and if any secret
// would not survive structural splitting (it must sit whole inside one string
// leaf to be highlightable), the ENTIRE body falls back to flat highlighted
// text. Mixed prose+JSON and non-JSON content use the flat path unchanged.

// Parse a body for tree display: a whole-content JSON doc, optionally behind
// the "Name: {…}" convention the mappers write. Returns null → use flat path.
function parseForTree(content, leaks) {
  // Cap tree-building at 1MB, not lower: real agent requests routinely run
  // 100KB+ (the whole conversation rides every turn), and those are exactly
  // the bodies that need folding most. Big trees are safe because JsonNode
  // builds children only while OPEN — a collapsed subtree is zero DOM — so
  // the initial render is just the expanded spine; the linear costs here
  // (JSON.parse + the R7 string walk) are trivial at this scale. Only a
  // pathological multi-MB body falls back to flat text.
  if (content.length > 1_000_000) return null;
  const m = content.match(NAMED_HEAD);
  const raw = (m ? m[2] : content).trim();
  if (!raw.startsWith("{") && !raw.startsWith("[")) return null;
  let value;
  try { value = JSON.parse(raw); } catch { return null; }
  if (value === null || typeof value !== "object") return null;
  // R7 backstop: every detected value present in the body must be wholly
  // visible inside a single string leaf, or the tree cannot highlight it.
  const strings = collectStrings(value);
  for (const l of leaks ?? []) {
    if (l.value && content.includes(l.value) && !strings.some((s) => s.includes(l.value))) {
      return null;
    }
  }
  return { head: m ? m[1] : null, value };
}

// Every string a tree renders as its own text node: leaves AND keys (both are
// highlight surfaces). The R7 "does the secret survive structural splitting"
// checks in parseForTree and parseSegments share this walk.
function collectStrings(value) {
  const strings = [];
  (function walk(v) {
    if (typeof v === "string") strings.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") {
      for (const [k, x] of Object.entries(v)) { strings.push(k); walk(x); }
    }
  })(value);
  return strings;
}

// Mixed prose+JSON bodies — the Mode B tool-row shape (`tool\n{args}\noutput…`)
// — split by LINE into text segments and foldable JSON trees. parseForTree
// only folds a body that IS one JSON document, so the args line of a codex
// tool row rendered flat. Exported for tests (pure data, no DOM).
// Returns null — keep the flat path — unless at least one line parses as a
// JSON object/array, and null again if ANY detected value present in the body
// would not survive the split whole (R7): a leak must sit inside a single
// text segment, or inside one string leaf of a single tree segment.
export function parseSegments(content, leaks) {
  if (content.length > 1_000_000) return null; // same ceiling as parseForTree
  const segs = [];
  let buf = [];
  const flush = () => {
    if (buf.length) segs.push({ kind: "text", text: buf.join("\n") });
    buf = [];
  };
  for (const line of content.split("\n")) {
    const t = line.trim();
    const named = t.match(NAMED_HEAD);
    const raw = named ? named[2] : t;
    let value;
    if (raw.startsWith("{") || raw.startsWith("[")) {
      try { value = JSON.parse(raw); } catch { /* prose after all */ }
    }
    if (value === null || typeof value !== "object") {
      buf.push(line);
      continue;
    }
    flush();
    segs.push({ kind: "tree", head: named ? named[1] : null, value });
  }
  flush();
  if (!segs.some((s) => s.kind === "tree")) return null;
  for (const l of leaks ?? []) {
    if (!l.value || !content.includes(l.value)) continue;
    const survives = segs.some((s) =>
      s.kind === "text" ? s.text.includes(l.value) : collectStrings(s.value).some((str) => str.includes(l.value)),
    );
    if (!survives) return null;
  }
  return segs;
}

function JsonNode({ k, v, leaks, depth, find }) {
  const isObj = v !== null && typeof v === "object";
  // Highlight the KEY too, not just values: a structured detector can match a
  // secret sitting in a key position (e.g. {"AKIA…": …}), and parseForTree
  // counts keys as highlightable — so they must actually carry the mark (R7).
  const key = k !== undefined &&
    html`<span class="jt-k"><${Highlighted} text=${String(k)} leaks=${leaks} find=${find} /></span><span class="jt-p">: </span>`;
  if (!isObj) {
    return html`<div class="jt-row">
      ${key}${typeof v === "string"
        ? html`<span class="jt-p">"</span><span class="jt-s"><${Highlighted} text=${v} leaks=${leaks} find=${find} /></span><span class="jt-p">"</span>`
        : html`<span class="jt-v">${JSON.stringify(v)}</span>`}
    </div>`;
  }
  const entries = Array.isArray(v) ? v.map((x, i) => [i, x]) : Object.entries(v);
  // A subtree carrying a secret must not start folded (R7). One carrying the
  // searched term starts open too — the user came here to see that match.
  // Lazy initializer, and the stringify lives inside it: the serialization and
  // the leak/find scans only decide the MOUNT state, and every SSE refresh
  // re-renders the whole transcript — paying a per-node subtree stringify on
  // each of those renders was pure waste.
  const [open, setOpen] = useState(() => {
    const json = JSON.stringify(v);
    const holdsLeak = (leaks ?? []).some((l) => l.value && json.includes(l.value));
    return holdsLeak || hasFind(json, find) || depth === 0 || json.length <= 160;
  });
  const [o, c] = Array.isArray(v) ? ["[", "]"] : ["{", "}"];
  if (entries.length === 0) return html`<div class="jt-row">${key}<span class="jt-p">${o}${c}</span></div>`;
  return html`<div>
    <div class="jt-row jt-toggle" onClick=${() => setOpen(!open)}>
      <span class="jt-chev" aria-hidden="true">${open ? "▾" : "▸"}</span>
      ${key}<span class="jt-p">${o}</span>
      ${!open && html`<span class="jt-preview"> ${entries.length} ${Array.isArray(v) ? "items" : "keys"} </span><span class="jt-p">${c}</span>`}
    </div>
    ${open && html`
      <div class="jt-kids">
        ${entries.map(([ck, cv]) => html`<${JsonNode} key=${String(ck)} k=${ck} v=${cv} leaks=${leaks} depth=${depth + 1} find=${find} />`)}
      </div>
      <div class="jt-row"><span class="jt-p">${c}</span></div>`}
  </div>`;
}

// Long-content guard: a CSS max-height clamp with a fade + expander. The text
// itself is never sliced, so Highlighted always sees the full content and a
// secret can never be bisected by a truncation point. Content holding the
// searched term starts expanded — the fold must not hide the match the user
// came for (they can still collapse it).
function ClampedText({ content, leaks, threshold, hasLeak, find }) {
  // Lazy: the fold of the whole body decides only the mount state.
  const [expanded, setExpanded] = useState(() => hasFind(content, find));
  const clampable = content.length > threshold && !hasLeak;
  if (!clampable) return html`<${Highlighted} text=${content} leaks=${leaks} find=${find} />`;
  return html`
    <div class=${expanded ? "clamp" : "clamp clamped"}>
      <${Highlighted} text=${content} leaks=${leaks} find=${find} />
    </div>
    <button class="expander" onClick=${() => setExpanded(!expanded)}>
      ${expanded ? "▴ collapse" : "▾ show all"}
    </button>
  `;
}

// Mixed prose+JSON body: prose renders as flat highlighted text, each JSON
// line as its own foldable tree. Clamping matches ClampedText exactly — the
// leak-bearing case never clamps (R7), the find-bearing case starts expanded,
// and the text is never sliced.
function MixedBody({ segments, content, leaks, threshold, hasLeak, find }) {
  // Lazy: same as ClampedText — mount-only decision, don't refold per render.
  const [expanded, setExpanded] = useState(() => hasFind(content, find));
  const clampable = content.length > threshold && !hasLeak;
  const body = segments.map((s, i) =>
    s.kind === "text"
      ? html`<div key=${i}><${Highlighted} text=${s.text} leaks=${leaks} find=${find} /></div>`
      : html`<div class="jt" key=${i}>
          ${s.head != null && html`<div class="jt-head">${s.head}</div>`}
          <${JsonNode} v=${s.value} leaks=${leaks} depth=${0} find=${find} />
        </div>`,
  );
  if (!clampable) return html`${body}`;
  return html`
    <div class=${expanded ? "clamp" : "clamp clamped"}>${body}</div>
    <button class="expander" onClick=${() => setExpanded(!expanded)}>
      ${expanded ? "▴ collapse" : "▾ show all"}
    </button>
  `;
}

// The one entry point every readable body goes through: tree when the content
// is a single JSON document, mixed prose+trees when JSON lines are embedded in
// other text, today's flat highlighted text otherwise. `find` (the searched
// term, when the user arrived from search) only marks and unfolds — it is
// never an input to the parse decisions, so a view with and without it shows
// the same structure.
export function JsonBody({ content, leaks, threshold, hasLeak, find }) {
  // Memoized: with the 1MB cap a parse is no longer trivially cheap, and every
  // SSE-driven refresh re-renders the whole transcript (and every JsonBody in
  // it). content/leaks come from stable fetched view state, so this only
  // recomputes when the body actually changes.
  const tree = useMemo(() => parseForTree(content, leaks), [content, leaks]);
  const segments = useMemo(
    () => (tree ? null : parseSegments(content, leaks)),
    [tree, content, leaks],
  );
  if (tree) {
    return html`<div class="jt">
      ${tree.head != null && html`<div class="jt-head">${tree.head}</div>`}
      <${JsonNode} v=${tree.value} leaks=${leaks} depth=${0} find=${find} />
    </div>`;
  }
  if (segments) {
    return html`<${MixedBody} segments=${segments} content=${content} leaks=${leaks}
      threshold=${threshold ?? 2500} hasLeak=${hasLeak} find=${find} />`;
  }
  return html`<${ClampedText} content=${prettyContent(content, leaks)} leaks=${leaks}
    threshold=${threshold ?? 2500} hasLeak=${hasLeak} find=${find} />`;
}

// Raw payloads keep all protocol fields that the readable projection omits,
// but JSON should still be navigable. The default is the same safe foldable
// tree used elsewhere; "exact text" remains one click away for inspecting the
// stored whitespace and escaping. Bodies that contain no structurally safe
// JSON stay verbatim, without offering a meaningless toggle.
export function rawCanFold(body, leaks) {
  if (!body) return false;
  return parseForTree(body, leaks) !== null || parseSegments(body, leaks) !== null;
}

export function RawBody({ body, leaks, find }) {
  const foldable = useMemo(() => rawCanFold(body, leaks), [body, leaks]);
  const [exact, setExact] = useState(false);
  if (!body) return html`<pre>(empty)</pre>`;
  if (!foldable) {
    return html`<pre class="rawblock"><${Highlighted} text=${body} leaks=${leaks} find=${find} /></pre>`;
  }
  return html`
    <div class="rawblock">
      <div class="raw-tools">
        <button onClick=${() => setExact(!exact)}>${exact ? "fold JSON" : "exact text"}</button>
      </div>
      ${exact
        ? html`<div class="raw-verbatim"><${Highlighted} text=${body} leaks=${leaks} find=${find} /></div>`
        : html`<${JsonBody} content=${body} leaks=${leaks} hasLeak=${(leaks ?? []).length > 0} find=${find} />`}
    </div>
  `;
}
