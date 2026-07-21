import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
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

  test("an interrupted write cannot corrupt the live file into a silent default", () => {
    // Model a crash mid-write: the atomic writer stages bytes in a temp file and
    // only renames on success. A process killed before the rename orphans the
    // temp and leaves the LIVE file untouched. Readers only ever open the target,
    // so a stray temp is inert and the previous good file still loads intact — a
    // plain in-place writeFileSync would instead have truncated it on the way.
    const dir = mkdtempSync(join(tmpdir(), "beagle-durable-"));
    const p = join(dir, "cfg.json");
    writeFileAtomic(p, JSON.stringify({ payloadWindowDays: 30 })); // the good file
    writeFileSync(join(dir, ".cfg.json.99999.tmp"), '{"payloadWindowDays": 3'); // orphaned scratch
    const r = loadJsonFile(p);
    expect(r.status).toBe("ok");
    expect((r as { value: { payloadWindowDays: number } }).value.payloadWindowDays).toBe(30);
  });
});
