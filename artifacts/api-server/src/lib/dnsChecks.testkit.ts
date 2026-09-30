import { it, vi, beforeEach, afterEach } from "vitest";
import { checkSpf } from "./dnsChecks.js";

/**
 * DNS check tests — stubs globalThis.fetch to simulate Cloudflare DoH responses.
 * All tests use status=0 (NOERROR) to exercise the actual check logic,
 * not the "network failure" early-return path.
 */

// ─── DoH mock helpers ─────────────────────────────────────────────────────────

export const TXT = 16, MX = 15, CNAME = 5;

/**
 * A real DoH answer section always carries the record type, and it contains the
 * whole resolution chain rather than only the type asked for. The fixtures omitted
 * `type` entirely, which is why a CNAME being counted as an MX record could not
 * have been caught here.
 */
export function dohResponse(answers: { data: string; type?: number }[], status = 0, defaultType = TXT): Response {
  const Answer = answers.map((a) => ({
    name: "example.com",
    type: a.type ?? defaultType,
    TTL: 300,
    data: a.data,
  }));
  return new Response(JSON.stringify({ Status: status, Answer }), {
    status: 200,
    headers: { "content-type": "application/dns-json" },
  });
}

export const noTxt = () => dohResponse([]);
export const noMx  = () => dohResponse([]);
export const hasMx = () => dohResponse([{ data: "10 mail.example.com.", type: MX }], 0, MX);

// ─── Setup / teardown ─────────────────────────────────────────────────────────

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

// ─── checkSpf — missing record ───────────────────────────────────────────────
