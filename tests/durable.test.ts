import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadJsonFile, writeFileAtomic } from "../src/core/fs/durable";

describe("loadJsonFile — missing/ok/corrupt are values, never a throw or a write", () => {
  test("missing file → status 'missing', nothing created", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-durable-"));
    const r = loadJsonFile(join(dir, "x.json"));
    expect(r.status).toBe("missing");
    expect(existsSync(join(dir, "x.json"))).toBe(false);
  });

  test("valid JSON → status 'ok' with the parsed value", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-durable-"));
    const p = join(dir, "x.json");
    writeFileSync(p, JSON.stringify({ a: 1 }));
    expect(loadJsonFile(p)).toEqual({ status: "ok", value: { a: 1 } });
  });

  test("truncated / garbage JSON → status 'corrupt', and the file is left untouched", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-durable-"));
    const p = join(dir, "x.json");
    writeFileSync(p, '{"a": 1,'); // truncated mid-object
    const before = readFileSync(p, "utf8");
    expect(loadJsonFile(p).status).toBe("corrupt");
    expect(readFileSync(p, "utf8")).toBe(before); // read-only: never repairs on disk
  });
});

describe("writeFileAtomic — temp → fsync → rename; 0600; never partial", () => {
  test("writes complete content at 0600, creating the parent dir, leaving no temp", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-durable-"));
    const p = join(dir, "sub", "cfg.json"); // parent dir does not exist yet
    writeFileAtomic(p, JSON.stringify({ hello: "world" }));
    expect(JSON.parse(readFileSync(p, "utf8"))).toEqual({ hello: "world" });
    expect(statSync(p).mode & 0o777).toBe(0o600);
    // The rename consumed the scratch file — nothing partial is left behind.
    expect(readdirSync(join(dir, "sub")).filter((n) => n.endsWith(".tmp"))).toEqual([]);
  });

  test("overwrites wholesale — a shorter payload can't leave a tail of the old one", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-durable-"));
    const p = join(dir, "cfg.json");
    writeFileAtomic(p, "AAAA");
    writeFileAtomic(p, "B"); // a non-atomic in-place write could leave "BAAA"
    expect(readFileSync(p, "utf8")).toBe("B");
  });

  test("accepts a binary payload (the install.key path)", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-durable-"));
    const p = join(dir, "install.key");
    const key = new Uint8Array([1, 2, 3, 4]);
    writeFileAtomic(p, key);
    expect(new Uint8Array(readFileSync(p))).toEqual(key);
  });

  test("an interrupted write leaves the previous good file loadable (a stray temp is inert)", () => {
    // Models the aftermath of a crash mid-write: the atomic writer only renames on
    // success, so a process killed before the rename orphans the temp and leaves
    // the LIVE file untouched. Readers open only the target, so the stray temp is
    // inert and the previous good file still loads — an in-place writeFileSync
    // would instead have truncated it on the way.
    const dir = mkdtempSync(join(tmpdir(), "beagle-durable-"));
    const p = join(dir, "cfg.json");
    writeFileAtomic(p, JSON.stringify({ payloadWindowDays: 30 })); // the good file
    writeFileSync(join(dir, ".cfg.json.99999.tmp"), '{"payloadWindowDays": 3'); // orphaned scratch
    const r = loadJsonFile(p);
    expect(r.status).toBe("ok");
    expect((r as { value: { payloadWindowDays: number } }).value.payloadWindowDays).toBe(30);
  });

  test("a failed write unlinks its temp and rethrows — no orphaned scratch, target untouched", () => {
    // Force a failure AFTER the temp is written: renaming a file onto an existing
    // directory throws. The catch must unlink the scratch file and rethrow.
    const dir = mkdtempSync(join(tmpdir(), "beagle-durable-"));
    const target = join(dir, "iamdir");
    mkdirSync(target); // target is a directory → renameSync(tmp, target) fails
    expect(() => writeFileAtomic(target, "data")).toThrow();
    expect(readdirSync(dir).filter((n) => n.endsWith(".tmp"))).toEqual([]); // cleaned up
  });

  test("a large payload is written whole (guards the writeSync short-write footgun)", () => {
    // writeSync issues one syscall and may short-write; writeFileSync loops. A
    // multi-MB round-trip that parses back intact would catch a regression to the
    // single-syscall form.
    const dir = mkdtempSync(join(tmpdir(), "beagle-durable-"));
    const p = join(dir, "big.json");
    const big = { blob: "x".repeat(5_000_000) };
    writeFileAtomic(p, JSON.stringify(big));
    expect(JSON.parse(readFileSync(p, "utf8")).blob.length).toBe(5_000_000);
  });
});
