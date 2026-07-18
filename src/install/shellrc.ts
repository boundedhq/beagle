// Shell-rc PATH block (design §6.7/§6.12): when coverage verification finds
// the shim dir isn't winning PATH, Beagle offers to fix it itself — one
// marker-guarded block appended to the user's shell rc, recorded in the
// change manifest, removed by unwatch-of-last-agent and uninstall. The
// markers make the edit idempotent (re-watch replaces, never stacks) and
// mechanically reversible (remove strips exactly what Beagle added).
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export const RC_BEGIN = "# >>> beagle shims >>>";
export const RC_END = "# <<< beagle shims <<<";

export interface RcTarget {
  path: string; // the rc file to edit
  line: string; // the PATH line, shown to the user before consent
}

// Which rc file does this user's interactive shell actually read?
// zsh honors ZDOTDIR; macOS terminals run bash as a LOGIN shell (reads
// .bash_profile, often never .bashrc); fish has its own config + syntax.
// Unknown shells return null — the caller falls back to printed instructions.
export function rcTargetFor(
  shell: string,
  home: string,
  platform: NodeJS.Platform,
  shimDir: string,
  zdotdir?: string,
): RcTarget | null {
  const name = shell.split("/").pop() ?? "";
  if (name === "zsh") {
    // `|| home`, not `??`: ZDOTDIR set-but-empty means "unset" to zsh, and an
    // empty string here would resolve to ./.zshrc in whatever CWD we run from.
    return { path: join(zdotdir || home, ".zshrc"), line: exportLine(shimDir) };
  }
  if (name === "bash") {
    return {
      path: join(home, platform === "darwin" ? ".bash_profile" : ".bashrc"),
      line: exportLine(shimDir),
    };
  }
  if (name === "fish") {
    return {
      path: join(home, ".config", "fish", "config.fish"),
      line: `set -gx PATH ${rcQuote(shimDir)} $PATH`,
    };
  }
  return null;
}

// `$PATH` rides INSIDE the double quotes (it must expand); the dir itself is
// escaped for the three characters that still bite there. Matches the form
// the manual instructions have always shown.
function exportLine(shimDir: string): string {
  return `export PATH="${escapeInQuotes(shimDir)}:$PATH"`;
}

// Inside double quotes, POSIX shells (and fish ≥3.4) still expand `$var` and
// execute `$(…)` / backticks — so a shim dir literally named `/tmp/x$(cmd)`
// would run `cmd` on every shell start. Escape all four active characters;
// `$PATH` rides outside this (added by the template, not the dir).
function escapeInQuotes(s: string): string {
  return s.replace(/(["\\`$])/g, "\\$1");
}

// fish: the dir is its own quoted token; $PATH is a separate list variable.
function rcQuote(s: string): string {
  return `"${escapeInQuotes(s)}"`;
}

export function pathBlock(line: string): string {
  return [
    `${RC_BEGIN} managed by 'beagle watch'; removed by 'beagle unwatch' / 'beagle uninstall'`,
    line,
    RC_END,
  ].join("\n");
}

// Find a marker only where it starts a line — so a user who COMMENTS OUT the
// block (`## >>> beagle shims >>>`) or pastes the marker text into a comment
// doesn't create a false boundary that install/remove would then act on
// mid-line, silently re-activating or deleting user content.
function lineAnchoredIndex(text: string, marker: string, from = 0): number {
  let i = text.indexOf(marker, from);
  while (i !== -1) {
    if (i === 0 || text[i - 1] === "\n") return i;
    i = text.indexOf(marker, i + 1);
  }
  return -1;
}

/** True when the rc has a begin marker with no matching end — an ambiguous
 *  block installPathBlock refuses to touch. Exposed so the caller can decide
 *  (and record the manifest entry) BEFORE attempting the mutation, instead of
 *  recording an edit that then gets refused. */
export function pathBlockMalformed(rcPath: string): boolean {
  if (!existsSync(rcPath)) return false;
  const current = readFileSync(rcPath, "utf8");
  const begin = lineAnchoredIndex(current, RC_BEGIN);
  return begin !== -1 && lineAnchoredIndex(current, RC_END, begin) === -1;
}

/** Append (or replace) the guarded block. Creates the rc file/dirs if absent.
 *  Idempotent: an existing block is rewritten in place, never duplicated.
 *  A MALFORMED block (begin marker without its end) refuses: writing a second
 *  block would leave two begin markers, and a later remove could then strip
 *  user content between them. `ok:false` → the caller falls back to printed
 *  instructions. */
export function installPathBlock(rcPath: string, line: string): { ok: boolean; changed: boolean } {
  const block = pathBlock(line);
  const current = existsSync(rcPath) ? readFileSync(rcPath, "utf8") : null;
  if (current === null) {
    mkdirSync(dirname(rcPath), { recursive: true });
    writeFileSync(rcPath, block + "\n", { mode: 0o644 });
    return { ok: true, changed: true };
  }
  const begin = lineAnchoredIndex(current, RC_BEGIN);
  if (begin !== -1) {
    const endMark = lineAnchoredIndex(current, RC_END, begin);
    if (endMark === -1) return { ok: false, changed: false }; // malformed — hands off
    const end = endMark + RC_END.length;
    const replaced = current.slice(0, begin) + block + current.slice(end);
    if (replaced === current) return { ok: true, changed: false };
    writeFileSync(rcPath, replaced);
    return { ok: true, changed: true };
  }
  const sep = current.endsWith("\n") ? "\n" : "\n\n";
  writeFileSync(rcPath, current + sep + block + "\n");
  return { ok: true, changed: true };
}

/** Strip the guarded block. Missing file / no markers → no-op (false).
 *  `mustReference` (this install's shim dir) scopes the removal: if the block
 *  on disk references a DIFFERENT shim dir — another state dir re-took the
 *  shared rc file — leave it alone rather than delete the other install's
 *  coverage. */
export function removePathBlock(rcPath: string, mustReference?: string): boolean {
  if (!existsSync(rcPath)) return false;
  const current = readFileSync(rcPath, "utf8");
  const begin = lineAnchoredIndex(current, RC_BEGIN);
  if (begin === -1) return false;
  const endMark = lineAnchoredIndex(current, RC_END, begin);
  // A begin marker with no end: don't guess at boundaries — leave the file
  // alone rather than delete user content.
  if (endMark === -1) return false;
  let end = endMark + RC_END.length;
  if (mustReference !== undefined && !current.slice(begin, end).includes(escapeInQuotes(mustReference))) {
    return false; // block belongs to a different install — not ours to remove
  }
  if (current[end] === "\n") end++;
  // Also absorb the blank separator line the install added, if present.
  let start = begin;
  if (current.slice(0, start).endsWith("\n\n")) start--;
  writeFileSync(rcPath, current.slice(0, start) + current.slice(end));
  return true;
}

