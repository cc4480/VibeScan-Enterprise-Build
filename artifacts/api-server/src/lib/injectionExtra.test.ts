import { describe, it, expect, afterEach } from "vitest";
import { runExtraInjectionProbes, evaluatedSyntax } from "./injectionExtra";
import { rendersAsHtml } from "./injectionProbe";
import { serve as listen, closeServers } from "./testkit";

afterEach(closeServers);

// A real server on loopback: `page(url)` returns the body, `headers(url)` any extra response headers. Every request it
// receives is recorded, so a test can say what the probe did and did not send.
let origin = "";
let hits: string[] = [];
async function serve(page: (u: URL) => string, headers: (u: URL) => Record<string, string> = () => ({})) {
  hits = [];
  const port = await listen((req, res) => {
    hits.push(req.url ?? "");
    const u = new URL(req.url ?? "/", "http://127.0.0.1");
    res.writeHead(200, { "content-type": "text/html", ...headers(u) });
    res.end(page(u));
  });
  origin = `http://127.0.0.1:${port}`;
}
const run = (cases = [{ path: "/greet", param: "name" }]) => runExtraInjectionProbes(origin, cases);

/** Evaluates ${a*b}: what a vulnerable template engine does. */
const evaluate = (v: string) => v.replace(/\$\{(\d+)\*(\d+)\}/g, (_m, a, b) => String(Number(a) * Number(b)));

describe("server-side template injection", () => {
  it("flags a server that evaluates an expression, and names the syntax", async () => {
    await serve((u) => `<h1>Hello ${evaluate(u.searchParams.get("name") ?? "")}</h1>`);
    const out = await run();
    expect(out.map((f) => f.name)).toEqual(["Server-Side Template Injection"]);
    expect(out[0]!.evidence).toContain("${ }");
    expect(out[0]!.evidence).toContain("/greet?name=");
  });

  it("clean twin: a server that echoes the expression as text does not fire", async () => {
    await serve((u) => `<h1>Hello ${u.searchParams.get("name")}</h1>`);
    expect(await run()).toEqual([]);
  });

  it("clean twin: a page that merely contains the product number elsewhere does not fire", async () => {
    await serve(() => `<p>Order 28146 shipped</p>`);
    expect(await run()).toEqual([]);
  });

  it("finds the syntax by the fences around the product, not the product alone", () => {
    const f = ["A", "B", "C", "D", "E"];
    expect(evaluatedSyntax("xA28146By", f)).toContain("{{ }}");
    expect(evaluatedSyntax("xC28146Dy", f)).toContain("<%=");
    expect(evaluatedSyntax("28146", f)).toBeNull();
    expect(evaluatedSyntax("A28146C", f)).toBeNull();
  });
});

describe("header injection", () => {
  it("flags a server that writes the line break into its headers", async () => {
    await serve(() => "ok", (u) => {
      const v = u.searchParams.get("name") ?? "";
      const m = /\r\n(x-sq-[a-z0-9]+): (\S+)/.exec(v);
      return m ? { [m[1]!]: m[2]! } : {};
    });
    const out = await run();
    expect(out.map((f) => f.name)).toEqual(["HTTP Header Injection (CRLF)"]);
  });

  it("clean twin: a server that encodes or strips the line break does not fire", async () => {
    await serve(() => "ok", () => ({ "x-echo": "sanitised" }));
    expect(await run()).toEqual([]);
  });
});

describe("safety", () => {
  it("never probes an endpoint whose name says it performs an action", async () => {
    await serve(() => "ok");
    await run([{ path: "/account/delete", param: "id" }]);
    expect(hits).toHaveLength(0);
  });

  it("tests at most ten parameters", async () => {
    await serve(() => "ok");
    await run(Array.from({ length: 30 }, (_, i) => ({ path: "/p", param: `p${i}` })));
    // two requests per parameter
    expect(hits).toHaveLength(20);
  });

  it("treats a network failure as nothing found", async () => {
    // A port that was open and is now closed: the connection is genuinely refused.
    await serve(() => "ok");
    await closeServers();
    expect(await run()).toEqual([]);
  });
});

describe("rendersAsHtml (reflected XSS needs a page a browser will parse as HTML)", () => {
  it.each([["text/html; charset=utf-8", true], ["application/xhtml+xml", true], ["", true], ["application/json", false], ["text/plain", false], ["image/svg+xml", false]])(
    "%s -> %s", (ct, expected) => expect(rendersAsHtml(ct)).toBe(expected),
  );
});
