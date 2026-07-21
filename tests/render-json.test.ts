import { describe, expect, test } from "bun:test";
import { parseSegments } from "../src/viewer/static/render-json.module.js";

// Mode B tool rows persist mixed prose+JSON bodies (`tool\n{args}\noutput…`),
// which the whole-document tree path can't fold — the args JSON rendered flat.
// parseSegments is the pure split behind the mixed renderer: prose stays text,
// each JSON LINE becomes a foldable tree, and any leak value that would not
// survive the split forces the whole body back to flat (null).

const CODEX_BODY = [
  "exec_command",
  '{"cmd":"sed -n 1,240p SKILL.md","workdir":"/w","yield_time_ms":10000}',
  "Chunk ID: 2d10c7",
  "Wall time: 0.0000 seconds",
].join("\n");

describe("parseSegments (mixed prose+JSON bodies)", () => {
  test("splits a codex tool body into prose and a foldable args tree", () => {
    const segs = parseSegments(CODEX_BODY, [])!;
    expect(segs.map((s) => s.kind)).toEqual(["text", "tree", "text"]);
    expect(segs[0]).toMatchObject({ kind: "text", text: "exec_command" });
    expect(segs[1]).toMatchObject({ kind: "tree", head: null });
    expect((segs[1] as { value: { cmd: string } }).value.cmd).toBe("sed -n 1,240p SKILL.md");
    expect(segs[2]).toMatchObject({ kind: "text", text: "Chunk ID: 2d10c7\nWall time: 0.0000 seconds" });
  });

  test("folds a Name-prefixed JSON line, including MCP-length names", () => {
    // mcp__openaiDeveloperDocssearch_openai_docs is 43 chars — the old {0,40}
    // head cap silently refused exactly the names codex MCP servers produce.
    const body = 'mcp__openaiDeveloperDocssearch_openai_docs: [{"type":"text","text":"hit"}]';
    const segs = parseSegments(body, [])!;
    expect(segs).toHaveLength(1);
    expect(segs[0]).toMatchObject({ kind: "tree", head: "mcp__openaiDeveloperDocssearch_openai_docs" });
  });

  test("a body with no JSON line stays flat (null — the existing path)", () => {
    expect(parseSegments("just prose\nand more prose", [])).toBeNull();
    expect(parseSegments("looks like { but is not json }", [])).toBeNull();
  });

  test("a malformed JSON-looking line stays prose text", () => {
    const segs = parseSegments('note\n{"unterminated": tru\n{"ok":1}', [])!;
    expect(segs.map((s) => s.kind)).toEqual(["text", "tree"]);
    expect((segs[0] as { text: string }).text).toBe('note\n{"unterminated": tru');
  });

  test("R7: a leak value wholly inside one string leaf keeps the split", () => {
    const leaks = [{ value: "AKIAZQ3DRSTUVWXY2345", secretType: "aws", tier: "structured" }];
    const body = 'exec\n{"env":"AWS_KEY=AKIAZQ3DRSTUVWXY2345"}\ndone';
    expect(parseSegments(body, leaks)).not.toBeNull();
  });

  test("R7: a leak value straddling a prose/JSON boundary forces flat", () => {
    // The secret's first half ends the prose line, the rest opens the JSON
    // line: no single segment shows it whole, so the body must not split.
    const leaks = [{ value: 'SECRETHALF\n{"k":"ONE', secretType: "generic-api-key", tier: "possible" }];
    const body = 'prefix SECRETHALF\n{"k":"ONEmore"}';
    expect(parseSegments(body, leaks)).toBeNull();
  });

  test("R7: a leak value split across two JSON string leaves forces flat", () => {
    const leaks = [{ value: 'aaaa","b":"bbbb', secretType: "generic-api-key", tier: "possible" }];
    const body = 'x\n{"a":"aaaa","b":"bbbb"}';
    expect(parseSegments(body, leaks)).toBeNull();
  });

  test("R7: a leak value inside a prose segment is fine (flat text highlights it)", () => {
    const leaks = [{ value: "ghp_tokentokentokentoken", secretType: "github-pat", tier: "structured" }];
    const body = 'header ghp_tokentokentokentoken\n{"a":1}';
    expect(parseSegments(body, leaks)).not.toBeNull();
  });
});
