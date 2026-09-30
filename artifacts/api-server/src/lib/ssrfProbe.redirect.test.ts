import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";

// A real loopback collector stands in for the OOB endpoint, so the tests can
// tell who called it: the scanner's own redirect-follow, or the target's server.
let collectorBase = "";
const hitTokens = new Set<string>();
let n = 0;

vi.mock("./oobServer.js", () => ({
  isOobConfigured: () => true,
  registerOobToken: async () => {
    const token = `oobtok${n++}`;
    return { token, url: `${collectorBase}/api/oob/${token}` };
  },
  tokensWithInteractions: async (tokens: string[]) => new Set(tokens.filter((t) => hitTokens.has(t))),
}));

const { runSsrfProbes } = await import("./ssrfProbe.js");

const servers: http.Server[] = [];
async function serve(h: http.RequestListener): Promise<number> {
  const srv = http.createServer(h);
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return (srv.address() as AddressInfo).port;
}

beforeEach(async () => {
  hitTokens.clear();
  const port = await serve((req, res) => {
    const m = /^\/api\/oob\/([a-z0-9]+)/.exec(req.url ?? "");
    if (m) hitTokens.add(m[1]!);
    res.writeHead(200).end();
  });
  collectorBase = `http://127.0.0.1:${port}`;
  // Shrink only the probe's post-injection callback wait; keep real request timers.
  const realSetTimeout = globalThis.setTimeout;
  vi.spyOn(globalThis, "setTimeout").mockImplementation(((fn: () => void, ms?: number, ...a: unknown[]) =>
    realSetTimeout(fn, ms === 6_000 ? 300 : ms, ...a)) as typeof setTimeout);
});

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

async function run(targetUrl: string) {
  return runSsrfProbes({ scanId: "s", targetUrl, endpoints: [] });
}

describe("SSRF probe versus open redirects", () => {
  it.each(["next", "url", "redirect", "return_url", "callback"])(
    "does not report SSRF when the target only 302s to the %s parameter",
    async (param) => {
      const port = await serve((req, res) => {
        const dest = new URL(req.url!, "http://x").searchParams.get(param);
        res.writeHead(302, { Location: dest ?? "/" }).end();
      });
      expect(await run(`http://localhost:${port}/login?${param}=/home`)).toEqual([]);
      expect(hitTokens.size).toBe(0);
    },
  );

  it("still reports SSRF when the target's server fetches the planted URL", async () => {
    const port = await serve((req, res) => {
      const dest = new URL(req.url!, "http://x").searchParams.get("url");
      if (dest) {
        http.get(dest, (r) => { r.resume(); res.writeHead(200).end("fetched"); })
          .on("error", () => res.writeHead(502).end());
      } else res.writeHead(200).end();
    });
    const found = await run(`http://localhost:${port}/preview?url=http://example.com`);
    expect(found).toHaveLength(1);
    expect(found[0]!.name).toMatch(/SSRF/);
  });
});
