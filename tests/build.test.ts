import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("compiled binary", () => {
  test(
    "binary works OUTSIDE the repo: daemon starts, embedded scanner catches a leak",
    async () => {
      // Regression for the v1 ship-blocker: rules, viewer statics, and the
      // scan worker must be embedded — no repo checkout at runtime.
      const dir = mkdtempSync(join(tmpdir(), "beagle-build-"));
      const out = join(dir, "beagle");
      const build = Bun.spawnSync([
        "bun", "build", "--compile",
        "src/cli/main.ts", "src/adapters/scan-worker-entry.ts",
        "--outfile", out,
      ], { cwd: join(import.meta.dir, "..") });
      expect(build.exitCode).toBe(0);

      const run = Bun.spawnSync([out, "--version"], { cwd: dir });
      expect(run.exitCode).toBe(0);
      expect(run.stdout.toString()).toMatch(/^beagle \d+\.\d+\.\d+/);

      // fake upstream
      const { createServer, connect } = await import("node:net");
      const upstream = createServer((sock) => {
        sock.on("data", () => sock.write("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}"));
        sock.on("error", () => {});
      });
      await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
      const upPort = (upstream.address() as { port: number }).port;

      const stateDir = join(dir, "state");
      const daemon = Bun.spawn([out, "daemon"], {
        cwd: dir, // critically: not the repo
        env: { ...process.env, BEAGLE_STATE_DIR: stateDir },
        stdio: ["ignore", "pipe", "pipe"],
      });
      try {
        // wait for daemon.json
        let info: { proxyPort: number; socketPath: string } | null = null;
        for (let i = 0; i < 50 && !info; i++) {
          await Bun.sleep(100);
          if (existsSync(join(stateDir, "daemon.json"))) {
            info = JSON.parse(readFileSync(join(stateDir, "daemon.json"), "utf8"));
          }
        }
        expect(info).not.toBeNull();

        // register a run over the control socket
        await new Promise<void>((resolve, reject) => {
          const sock = connect(info!.socketPath, () => {
            sock.write(JSON.stringify({
              cmd: "register-run",
              args: { id: "bt", agent: "claude-code", provider: "anthropic", upstream: `http://127.0.0.1:${upPort}` },
            }) + "\n");
          });
          sock.on("data", () => { sock.end(); resolve(); });
          sock.on("error", reject);
        });

        // send a leaking request through the proxy
        await fetch(`http://127.0.0.1:${info!.proxyPort}/run/bt/v1/messages`, {
          method: "POST",
          body: '{"messages":[{"role":"user","content":"key AKIAZQ3DRSTUVWXY2345"}]}',
        });

        // the embedded scanner must record the leak — poll, don't guess a
        // fixed delay (slow CI runners)
        let leaksOut = "";
        for (let i = 0; i < 40 && !leaksOut.includes("aws-access-key-id"); i++) {
          await Bun.sleep(150);
          leaksOut = Bun.spawnSync([out, "leaks"], {
            cwd: dir,
            env: { ...process.env, BEAGLE_STATE_DIR: stateDir },
          }).stdout.toString();
        }
        expect(leaksOut).toContain("aws-access-key-id");
      } finally {
        daemon.kill();
        upstream.close();
      }
    },
    120_000,
  );
});
