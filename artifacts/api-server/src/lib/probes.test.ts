import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { runWithScanHttp } from "./http.js";
import { checkErrorDisclosure, checkDirectoryListing } from "./probes.js";

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

describe("checkErrorDisclosure — regression: baseline diff", () => {
  it("does not flag a Warning: that is ordinary homepage copy, served by an SPA catch-all for the nonexistent path too", async () => {
    // The exact false positive this exists to prevent: a single-page app
    // answers every unmatched route — including the scan's deliberately
    // nonexistent probe path — with its normal shell, status 200. If that
    // shell happens to mention "Warning:" anywhere (an age gate, a shipping
    // notice), the old, undifferentiated check called that a leaked PHP
    // error.
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html><body>Warning: age-restricted content, 18+ only</body></html>");
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      checkErrorDisclosure(`http://localhost:${port}/`),
    );

    expect(findings).toEqual([]);
  });

  it("still catches a genuine PHP warning that only appears on the error path", async () => {
    const port = await serve((req, res) => {
      if ((req.url ?? "").includes("_vibescan-")) {
        res.writeHead(200, { "content-type": "text/html" });
        res.end("Warning: include(/var/www/config.php): failed to open stream in /var/www/index.php on line 12");
        return;
      }
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html><body>Welcome to the homepage</body></html>");
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      checkErrorDisclosure(`http://localhost:${port}/`),
    );

    expect(findings.length).toBe(1);
    expect(findings[0]!.name).toMatch(/Verbose Error Pages/i);
  });

  it("still flags the Werkzeug debugger as critical, distinctly from an ordinary leak", async () => {
    const port = await serve((req, res) => {
      if ((req.url ?? "").includes("_vibescan-")) {
        res.writeHead(500, { "content-type": "text/html" });
        res.end("Traceback (most recent call last)\nwerkzeug.debug.DebuggedApplication\nDebugger caught an exception");
        return;
      }
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html><body>Home page, working fine</body></html>");
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      checkErrorDisclosure(`http://localhost:${port}/`),
    );

    expect(findings.length).toBe(1);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.name).toMatch(/Werkzeug/i);
  });

  it("stays quiet when the nonexistent path and the homepage are identical", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html><body>ordinary site, nothing suspicious</body></html>");
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      checkErrorDisclosure(`http://localhost:${port}/`),
    );

    expect(findings).toEqual([]);
  });
});

describe("checkDirectoryListing — regression: weak pattern removed", () => {
  it("does not flag a documentation page with a horizontal rule followed by a code block", async () => {
    // <hr><pre> is real autoindex layout, but it is also exactly what a
    // markdown renderer produces for "---" followed by a fenced code block —
    // ordinary on a docs site, changelog or blog post.
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html><body><hr><pre>npm install example</pre></body></html>");
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      checkDirectoryListing(`http://localhost:${port}/`),
    );

    expect(findings).toEqual([]);
  });

  it("still catches a real Apache autoindex page", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(
        '<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1>' +
          '<a href="?C=N&amp;O=D">Name</a> [To Parent Directory]</body></html>',
      );
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      checkDirectoryListing(`http://localhost:${port}/`),
    );

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.name).toMatch(/Directory Listing/i);
  });
});
