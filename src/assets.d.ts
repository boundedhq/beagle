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
  // render-json.module.js is also imported as a REAL module by tests; its
  // pure (non-render) exports are typed here. Harmless for the text-import case.
  export function parseSegments(
    content: string,
    leaks: Array<{ value?: string }> | undefined,
  ): Array<{ kind: "text"; text: string } | { kind: "tree"; head: string | null; value: unknown }> | null;
  export function rawCanFold(
    body: string | null | undefined,
    leaks: Array<{ value?: string }> | undefined,
  ): boolean;
  export function findRuns(
    text: string | null | undefined,
    find: string | null | undefined,
  ): Array<{ text: string; hit: boolean }>;
  export function hasFind(text: unknown, find: string | null | undefined): boolean;
}
