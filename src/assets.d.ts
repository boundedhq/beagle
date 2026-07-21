// Embedded-asset imports (Bun `with { type: "text" }`): these resolve to the
// file's contents as a string, and `bun build --compile` embeds them in the
// binary — the fix for runtime readFileSync paths that don't exist outside
// the repo.
declare module "*.html" {
  const text: string;
  export default text;
}
declare module "*.css" {
  const text: string;
  export default text;
}
declare module "*.sha256" {
  const text: string;
  export default text;
}
declare module "*.json" {
  const text: string;
  export default text;
}
declare module "*/app.js" {
  const text: string;
  export default text;
}
declare module "*.module.js" {
  const text: string;
  export default text;
  // render-json.module.js is also imported as a REAL module by tests; its one
  // pure (non-render) export is typed here. Harmless for the text-import case.
  export function parseSegments(
    content: string,
    leaks: Array<{ value?: string }> | undefined,
  ): Array<{ kind: "text"; text: string } | { kind: "tree"; head: string | null; value: unknown }> | null;
}
