import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { runWithScanHttp } from "./http.js";
import { checkPathTraversal } from "./pathTraversal.js";

const servers: http.Server[] = [];

async function serve(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<number> {
  const srv = http.createServer(handler);
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return (srv.address() as AddressInfo).port;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

const HTML_WITH_FILE_PARAM =
  '<a href="/download?file=readme.txt">Download</a>';

describe("checkPathTraversal — regression: baseline diff", () => {
  it("does not flag a page whose normal content already contains a Windows-shaped bracket word", async () => {
    // The exact false-positive this exists to prevent: an SPA catch-all (or a
    // documentation page, or a markdown-rendered blog) that answers every
    // path with content mentioning "[Extensions]" or similar, regardless of
    // what payload was sent. Before the baseline diff, this alone was enough
    // to confirm LFI at the maximum severity the scanner assigns.
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html><body>Browse our [Extensions] and [Files]</body></html>");
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      checkPathTraversal(`http://localhost:${port}/`, HTML_WITH_FILE_PARAM),
    );

    expect(findings).toEqual([]);
  });

  it("still catches a genuine Linux LFI", async () => {
    // No baseline concern for the Linux signature in practice, but the fix
    // applies uniformly — confirm it still fires when the payload response
    // genuinely differs from an unmodified request.
    const port = await serve((req, res) => {
      const url = new URL(req.url ?? "/", "http://localhost");
      const file = url.searchParams.get("file") ?? "";
      if (file.includes("..") || file.includes("etc/passwd")) {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n");
        return;
      }
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("normal file contents");
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      checkPathTraversal(`http://localhost:${port}/`, HTML_WITH_FILE_PARAM),
    );

    expect(findings.length).toBe(1);
    expect(findings[0]!.name).toMatch(/Path Traversal/i);
  });

  it("still catches a genuine Windows LFI even though the signature words are common English", async () => {
    // The point of the fix is "not present in the baseline, present after the
    // payload" — not "never fire on these words." A real win.ini leak must
    // still be caught.
    const port = await serve((req, res) => {
      const url = new URL(req.url ?? "/", "http://localhost");
      const file = url.searchParams.get("file") ?? "";
      if (file.includes("win.ini") || file.includes("..")) {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("[fonts]\r\n[extensions]\r\n[mci extensions]\r\n[files]\r\n");
        return;
      }
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("<html>ordinary page, no bracket words at all</html>");
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      checkPathTraversal(`http://localhost:${port}/`, HTML_WITH_FILE_PARAM),
    );

    expect(findings.length).toBe(1);
    expect(findings[0]!.evidence).toContain("Windows");
  });

  it("stays quiet when nothing about the response changes at all", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("static content, identical for every request");
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      checkPathTraversal(`http://localhost:${port}/`, HTML_WITH_FILE_PARAM),
    );

    expect(findings).toEqual([]);
  });
});
