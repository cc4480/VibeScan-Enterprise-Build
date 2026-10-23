/**
 * Two more injection classes for injectionProbe.ts, both confirmed by something the
 * server does that our own random tokens make impossible to happen by accident:
 *
 *  SERVER-SIDE TEMPLATE INJECTION. One request carries four template expressions
 *  ({{…}}, ${…}, <%= … %>, #{…}), each computing the same unusual product and each
 *  fenced by its own random token. If the server evaluates one, the response holds
 *  "<token>28146<token>" between our fences. The product appearing between the right
 *  two tokens can only come from evaluation: an echoed payload contains the
 *  expression, not its result. Browser-side frameworks cannot cause it, because
 *  this reads the raw server response and runs no JavaScript.
 *
 *  HEADER (CRLF) INJECTION. The value carries a line break and a header named with a
 *  random token. The finding needs that header in the response, i.e. the server
 *  wrote our line break into its own headers. Redirects are not followed, since the
 *  injected header lands on the first response.
 *
 * Detection only: the expression is arithmetic and the header is inert. Nothing is
 * executed beyond multiplying two numbers, no data is read, and no file is touched.
 * Non-fatal: any error is "nothing found".
 */
import { randomUUID, randomBytes } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch } from "./http";
import { isDestructiveUrl } from "./destructive";

const TIMEOUT_MS = 7_000;
const MAX_CASES = 10;
const PRODUCT = "28146"; // 4691 * 6

export interface InjectionCase { path: string; param: string }

const SYNTAXES = [
  { engine: "{{ }} (Jinja2, Twig, Handlebars-style)", expr: "{{4691*6}}" },
  { engine: "${ } (Freemarker, Velocity, Spring EL, JS templates)", expr: "${4691*6}" },
  { engine: "<%= %> (ERB, EJS)", expr: "<%= 4691*6 %>" },
  { engine: "#{ } (Ruby, Pug)", expr: "#{4691*6}" },
];

const vuln = (partial: Omit<ScanVulnerability, "id">): ScanVulnerability => ({ id: randomUUID(), ...partial });

async function get(url: string, redirect: "follow" | "manual"): Promise<{ body: string; headers: Headers } | null> {
  const res = await scanFetch(url, { timeoutMs: TIMEOUT_MS, redirect });
  return res ? { body: res.body, headers: new Headers(res.headers) } : null;
}

/** Which template syntax, if any, the server evaluated; pure so it can be tested on its own. */
export function evaluatedSyntax(body: string, fences: string[]): string | null {
  for (let i = 0; i < SYNTAXES.length; i++) {
    if (body.includes(`${fences[i]}${PRODUCT}${fences[i + 1]}`)) return SYNTAXES[i]!.engine;
  }
  return null;
}

async function probeTemplate(origin: string, c: InjectionCase): Promise<{ engine: string } | null> {
  const fences = Array.from({ length: SYNTAXES.length + 1 }, () => "sq" + randomBytes(4).toString("hex"));
  const value = SYNTAXES.map((s, i) => `${fences[i]}${s.expr}`).join("") + fences[SYNTAXES.length];
  const url = new URL(`${origin}${c.path}`);
  url.searchParams.set(c.param, value);
  const res = await get(url.toString(), "follow");
  const engine = res ? evaluatedSyntax(res.body, fences) : null;
  return engine ? { engine } : null;
}

async function probeCrlf(origin: string, c: InjectionCase): Promise<boolean> {
  const name = "x-sq-" + randomBytes(4).toString("hex");
  const url = new URL(`${origin}${c.path}`);
  url.searchParams.set(c.param, `sq${randomBytes(3).toString("hex")}\r\n${name}: injected`);
  const res = await get(url.toString(), "manual");
  return res?.headers.get(name) === "injected";
}

export async function runExtraInjectionProbes(origin: string, cases: InjectionCase[]): Promise<ScanVulnerability[]> {
  const usable = cases.filter((c) => !isDestructiveUrl(`${origin}${c.path}`)).slice(0, MAX_CASES);
  const ssti: Array<InjectionCase & { engine: string }> = [];
  const crlf: InjectionCase[] = [];

  for (const c of usable) {
    // One odd response must not cost the rest of the scan, so each probe is its own try.
    try {
      const t = await probeTemplate(origin, c);
      if (t) ssti.push({ ...c, engine: t.engine });
    } catch { /* nothing found */ }
    try {
      if (await probeCrlf(origin, c)) crlf.push(c);
    } catch { /* nothing found */ }
  }

  const out: ScanVulnerability[] = [];
  if (ssti.length > 0) {
    const first = ssti[0]!;
    const params = [...new Set(ssti.map((s) => s.param))].join(", ");
    out.push(vuln({
      name: "Server-Side Template Injection",
      severity: "critical",
      category: "Injection",
      description:
        `The server evaluated a template expression sent in the ${params} parameter: an expression that multiplies two numbers came back as ` +
        "the computed result, not as the text sent. User input is being compiled as part of a template, which in most template engines " +
        "lets an attacker run code on the server and read its files and environment.",
      evidence: `Endpoint: ${first.path}?${first.param}=<expression>\nSyntax evaluated: ${first.engine}\nSent an expression computing 4691 × 6; the response contained ${PRODUCT} between two random tokens we placed around it.`,
      solution:
        "Never build a template from user input. Pass user data to the template as a variable (render(template, { name })), not by concatenating it into the template string. " +
        "Where users must author templates, use a logic-less or sandboxed engine and run rendering in a low-privilege process.",
      cweId: "CWE-1336",
      cvssScore: 9.8,
      wstgId: "WSTG-INPV-18",
      confidence: 95,
    }));
  }
  if (crlf.length > 0) {
    const first = crlf[0]!;
    out.push(vuln({
      name: "HTTP Header Injection (CRLF)",
      severity: "medium",
      category: "Injection",
      description:
        `A line break sent in the ${first.param} parameter was written into the response headers, so an attacker can add headers of their own. ` +
        "That enables cookie injection (session fixation), response splitting and cache poisoning.",
      evidence: `Endpoint: ${first.path}?${first.param}=<value>%0d%0a<header>\nThe response carried a header we injected (random name, value "injected").`,
      solution:
        "Strip or reject CR and LF from any value that reaches a response header (a redirect target, a cookie value, a custom header). " +
        "Current versions of most frameworks refuse this; if you build raw responses or run an old version, encode the value or upgrade.",
      cweId: "CWE-113",
      cvssScore: 6.1,
      wstgId: "WSTG-INPV-15",
      confidence: 95,
    }));
  }
  return out;
}
