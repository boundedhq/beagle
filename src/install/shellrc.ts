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

function escapeInQuotes(s: string): string {
  return s.replace(/(["\\`])/g, "\\$1");
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
  const begin = current.indexOf(RC_BEGIN);
  if (begin !== -1) {
    const endMark = current.indexOf(RC_END, begin);
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

/** Strip the guarded block. Missing file / no markers → no-op (false). */
export function removePathBlock(rcPath: string): boolean {
  if (!existsSync(rcPath)) return false;
  const current = readFileSync(rcPath, "utf8");
  const begin = current.indexOf(RC_BEGIN);
  if (begin === -1) return false;
  const endMark = current.indexOf(RC_END, begin);
  // A begin marker with no end: don't guess at boundaries — leave the file
  // alone rather than delete user content.
  if (endMark === -1) return false;
  let end = endMark + RC_END.length;
  if (current[end] === "\n") end++;
  // Also absorb the blank separator line the install added, if present.
  let start = begin;
  if (current.slice(0, start).endsWith("\n\n")) start--;
  writeFileSync(rcPath, current.slice(0, start) + current.slice(end));
  return true;
}

