// Safe body rendering — the ONE place a captured body becomes DOM, so the whole
// §6.8 / R7 audit surface lives in a single file. Every function here holds two
// invariants: (§6.8) captured text is only ever interpolated as a text node,
// never markup; (R7) a detected secret is always visibly highlighted — no fold
// or clamp ever hides one. Everything that shows a stored body goes through
// JsonBody (readable) or RawBody (raw); those are the only exports.
import { h } from "preact";
import { useMemo, useState } from "preact/hooks";
import htm from "htm";

const html = htm.bind(h);

// Renders text, wrapping each detected secret value in a red <mark>. Splits on
// values and builds text nodes only — never raw-HTML injection (§6.8).
function Highlighted({ text, leaks }) {
  if (!leaks || leaks.length === 0 || typeof text !== "string") return text ?? "";
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
    if (at === -1) { out.push(rest); break; }
    if (at > 0) out.push(rest.slice(0, at));
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

// Pretty-print JSON for reading, applied to EVERY displayed body: each line
// that parses as a JSON object/array (bare, or behind a "Name: " prefix like
// the Mode B "Bash: {...}" convention) re-serializes with 2-space indent.
// Guard: if reformatting would lose an inline secret highlight (the value no
// longer substring-matches), that line stays verbatim — a leak never loses
// its red mark to cosmetics.
function prettyContent(text, leaks) {
  const values = (leaks ?? []).map((l) => l.value).filter(Boolean);
  const out = text
    .split("\n")
    .map((line) => {
      const t = line.trim();
      const named = t.match(/^([A-Za-z_][\w.-]{0,40}):\s*([{[].*)$/);
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
  const m = content.match(/^([A-Za-z_][\w.-]{0,40}):\s*([\s\S]*)$/);
  const raw = (m ? m[2] : content).trim();
  if (!raw.startsWith("{") && !raw.startsWith("[")) return null;
  let value;
  try { value = JSON.parse(raw); } catch { return null; }
  if (value === null || typeof value !== "object") return null;
  // R7 backstop: every detected value present in the body must be wholly
  // visible inside a single string leaf, or the tree cannot highlight it.
  const strings = [];
  (function walk(v) {
    if (typeof v === "string") strings.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") {
      for (const [k, x] of Object.entries(v)) { strings.push(k); walk(x); }
    }
  })(value);
  for (const l of leaks ?? []) {
    if (l.value && content.includes(l.value) && !strings.some((s) => s.includes(l.value))) {
      return null;
    }
  }
  return { head: m ? m[1] : null, value };
}

function JsonNode({ k, v, leaks, depth }) {
  const isObj = v !== null && typeof v === "object";
  // Highlight the KEY too, not just values: a structured detector can match a
  // secret sitting in a key position (e.g. {"AKIA…": …}), and parseForTree
  // counts keys as highlightable — so they must actually carry the mark (R7).
  const key = k !== undefined &&
    html`<span class="jt-k"><${Highlighted} text=${String(k)} leaks=${leaks} /></span><span class="jt-p">: </span>`;
  if (!isObj) {
    return html`<div class="jt-row">
      ${key}${typeof v === "string"
        ? html`<span class="jt-p">"</span><span class="jt-s"><${Highlighted} text=${v} leaks=${leaks} /></span><span class="jt-p">"</span>`
        : html`<span class="jt-v">${JSON.stringify(v)}</span>`}
    </div>`;
  }
  const entries = Array.isArray(v) ? v.map((x, i) => [i, x]) : Object.entries(v);
  const json = JSON.stringify(v);
  // A subtree carrying a secret must not start folded (R7).
  const holdsLeak = (leaks ?? []).some((l) => l.value && json.includes(l.value));
  const [open, setOpen] = useState(holdsLeak || depth === 0 || json.length <= 160);
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
        ${entries.map(([ck, cv]) => html`<${JsonNode} key=${String(ck)} k=${ck} v=${cv} leaks=${leaks} depth=${depth + 1} />`)}
      </div>
      <div class="jt-row"><span class="jt-p">${c}</span></div>`}
  </div>`;
}

// Long-content guard: a CSS max-height clamp with a fade + expander. The text
// itself is never sliced, so Highlighted always sees the full content and a
// secret can never be bisected by a truncation point.
function ClampedText({ content, leaks, threshold, hasLeak }) {
  const [expanded, setExpanded] = useState(false);
  const clampable = content.length > threshold && !hasLeak;
  if (!clampable) return html`<${Highlighted} text=${content} leaks=${leaks} />`;
  return html`
    <div class=${expanded ? "clamp" : "clamp clamped"}>
      <${Highlighted} text=${content} leaks=${leaks} />
    </div>
    <button class="expander" onClick=${() => setExpanded(!expanded)}>
      ${expanded ? "▴ collapse" : "▾ show all"}
    </button>
  `;
}

// The one entry point every readable body goes through: tree when the content
// is a single JSON document, today's flat highlighted text otherwise.
export function JsonBody({ content, leaks, threshold, hasLeak }) {
  // Memoized: with the 1MB cap a parse is no longer trivially cheap, and every
  // SSE-driven refresh re-renders the whole transcript (and every JsonBody in
  // it). content/leaks come from stable fetched view state, so this only
  // recomputes when the body actually changes.
  const tree = useMemo(() => parseForTree(content, leaks), [content, leaks]);
  if (!tree) {
    return html`<${ClampedText} content=${prettyContent(content, leaks)} leaks=${leaks}
      threshold=${threshold ?? 2500} hasLeak=${hasLeak} />`;
  }
  return html`<div class="jt">
    ${tree.head != null && html`<div class="jt-head">${tree.head}</div>`}
    <${JsonNode} v=${tree.value} leaks=${leaks} depth=${0} />
  </div>`;
}

// The raw view's request/response body: the exact captured bytes, folded as a
// JSON tree when the body is one document (the common case — a wire request or
// response IS one), flat verbatim text otherwise. The same JsonBody every
// readable body uses ("all JSON folds"), but with clamping off (threshold 1e9)
// so the raw view never tucks anything behind a "show all". R7 rides along:
// JsonBody starts every leak-bearing subtree expanded, and if a secret can't
// survive the structural split it falls back to flat highlighted text.
export function RawBody({ body, leaks }) {
  if (!body) return html`<pre>(empty)</pre>`;
  return html`<div class="rawblock">
    <${JsonBody} content=${body} leaks=${leaks} threshold=${1e9} />
  </div>`;
}
