import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import { createHash } from "node:crypto";
import type { AddressInfo } from "node:net";
import { runWithScanHttp } from "./http";
import { scanContent, scanJavaScriptForSecrets } from "./jsScanner";

/**
 * The secret scanner reading a whole production bundle.
 *
 * A Vite build puts the libraries first and the app's own code last. The scanner used to keep the first
 * 512,000 bytes of a script, so on a 761,001-byte bundle of a Lovable-style app it never saw the app's code:
 * the service_role key (at byte 756,7xx) and an OpenAI key (a few hundred bytes after it) went unreported,
 * and the one place a service_role key could be recognised without its variable name, the token's own `role`
 * claim, was never reached. Nothing here is a working credential; the tokens carry real-looking claims and a
 * filler signature.
 */

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
// The signature is a hash of the claims, so it looks like the random bytes of a real one (a run of one character is
// judged a template by the scanner, which is right to).
const jwt = (claims: Record<string, unknown>) => {
  const head = `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}`;
  return `${head}.${createHash("sha256").update(head).digest("base64url")}`;
};
const REF = "abcdefghijklmnopqrst";
const ANON = jwt({ iss: "supabase", ref: REF, role: "anon", iat: 1700000000, exp: 2000000000 });
const SERVICE = jwt({ iss: "supabase", ref: REF, role: "service_role", iat: 1700000000, exp: 2000000000 });
const USER_TOKEN = jwt({ sub: "6f1c2d3e", role: "authenticated", email: "someone@example.test", iat: 1700000000 });
/** Shaped like an OpenAI project key; random-looking so it is not taken for a template. */
const OPENAI = "sk-proj-" + createHash("sha256").update("lab-openai-1").digest("base64url") + createHash("sha256").update("lab-openai-2").digest("base64url");

/** Library code, as a minifier leaves it. */
const FILLER = 'function Ee(e){return e}class Xt{constructor(e){this.opts=e}}const Q=e=>typeof e=="boolean"?`${e}`:e;';
const vendor = (bytes: number) => FILLER.repeat(Math.ceil(bytes / FILLER.length));

/** An app bundle: libraries first, the app's own code last. */
const bundle = (appCode: string, vendorBytes = 650_000) => vendor(vendorBytes) + appCode;

const appWith = (opts: { service?: boolean; openai?: boolean }) =>
  `const sM="https://${REF}.supabase.co",aM="${ANON}",Tn=cO(sM,aM,{auth:{persistSession:!0}});` +
  (opts.service ? `const fI=cO(sM,"${SERVICE}");` : "") +
  (opts.openai ? `const hI="${OPENAI}";async function ask(e){return(await fetch("https://api.openai.com/v1/chat/completions",{headers:{Authorization:\`Bearer \${hI}\`}})).json()}` : "");

const servers: http.Server[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r)))); });

async function scanBundle(js: string) {
  const srv = http.createServer((req, res) => {
    if (req.url === "/assets/index.js") res.writeHead(200, { "content-type": "application/javascript" }).end(js);
    else res.writeHead(404).end();
  });
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}/`;
  const html = `<html><head><script type="module" src="/assets/index.js"></script></head><body><div id="root"></div></body></html>`;
  return runWithScanHttp({ targetUrl: base }, () => scanJavaScriptForSecrets(html, base));
}

describe("the secret scanner reads the whole bundle", () => {
  it("finds the service_role key and the OpenAI key that sit after byte 512,000", async () => {
    const js = bundle(appWith({ service: true, openai: true }));
    expect(js.length).toBeGreaterThan(650_000);
    const found = await scanBundle(js);
    const names = found.map((f) => f.name);
    expect(names).toContain("Supabase Service Role Key Exposed in JavaScript");
    expect(names).toContain("OpenAI API Key Exposed");
    for (const n of ["Supabase Service Role Key Exposed in JavaScript", "OpenAI API Key Exposed"]) {
      expect(found.find((f) => f.name === n)?.severity).toBe("critical");
    }
  });

  it("reports the service_role key once, not also as a generic hardcoded JWT", async () => {
    const found = await scanBundle(bundle(appWith({ service: true })));
    expect(found.filter((f) => /Service Role/.test(f.name))).toHaveLength(1);
    expect(found.find((f) => /Hardcoded JWT/.test(f.name))).toBeUndefined();
  });

  it("never writes either key out whole in the evidence", async () => {
    const found = await scanBundle(bundle(appWith({ service: true, openai: true })));
    for (const f of found) {
      expect(f.evidence).not.toContain(SERVICE);
      expect(f.evidence).not.toContain(OPENAI);
    }
  });

  it("clean twin: the same bundle with only the public key reports nothing", async () => {
    const found = await scanBundle(bundle(appWith({})));
    expect(found).toEqual([]);
  });

  it("reads a script right up to the transport limit", async () => {
    // 4.9 MB of library code, then the app's code.
    const found = await scanBundle(bundle(appWith({ service: true }), 4_900_000));
    expect(found.map((f) => f.name)).toContain("Supabase Service Role Key Exposed in JavaScript");
  });
});

describe("a service_role key is recognised by its role claim, not by what it is called", () => {
  it("finds it under a name a minifier would leave", () => {
    const hits = scanContent(`const fI=cO(sM,"${SERVICE}");`).map((h) => h.pattern.name);
    expect(hits).toContain("Supabase Service Role Key Exposed in JavaScript");
    expect(hits).not.toContain("Hardcoded JWT Token in Source");
  });

  it("is reported once when the variable name matches too", async () => {
    const html = `<html><script>const serviceRoleKey = "${SERVICE}";</script></html>`;
    const found = await scanJavaScriptForSecrets(html, "http://127.0.0.1:9/");
    expect(found.filter((f) => /Service Role/.test(f.name))).toHaveLength(1);
  });

  it("does not take the public anon key for it", () => {
    expect(scanContent(`const aM="${ANON}";`)).toEqual([]);
  });

  it("still reports a signed-in user's token as a hardcoded credential", () => {
    const hits = scanContent(`const t="${USER_TOKEN}";`).map((h) => h.pattern.name);
    expect(hits).toEqual(["Hardcoded JWT Token in Source"]);
  });
});
