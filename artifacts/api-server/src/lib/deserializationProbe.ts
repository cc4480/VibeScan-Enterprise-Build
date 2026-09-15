// Insecure deserialization exposure (PASSIVE, detection-only). Flags a native
// serialized object stored in a COOKIE the server issued — a value the client
// controls and the server must deserialize on its next request, which is the
// root condition for insecure deserialization (CWE-502 / OWASP A08).
//
// Cookie-scoped on purpose. A serialized blob that only appears in a response
// BODY may be display-only and never reach a deserializer, but one round-tripped
// through a cookie is deserialized server-side by definition — the low-false-
// positive signal. SecScan is detection-only: no gadget chain is attempted, so
// this reports the exposure, never an exploit.
import type { ScanVulnerability } from "./scanner";

interface Marker {
  format: string;
  rx: RegExp;
  note: string;
}

// Anchored to each format's magic bytes / grammar, not loose base64 — a generic
// base64 value or a JWT must not match.
const MARKERS: Marker[] = [
  { format: "Java", rx: /rO0AB[A-Za-z0-9+/=]{8,}/, note: "base64 of the Java serialization stream header (AC ED 00 05)" },
  { format: "PHP", rx: /(?:^|[^A-Za-z0-9])O:\d{1,3}:"[^"]{1,120}":\d{1,4}:\{/, note: 'a PHP serialized object (O:len:"Class":n:{…})' },
  { format: "PHP", rx: /(?:^|[^A-Za-z0-9])a:\d{1,4}:\{[isbdOa]:/, note: "a PHP serialized array (a:n:{…})" },
  { format: "Ruby (Marshal)", rx: /BAh[A-Za-z0-9+/=]{16,}/, note: "base64 of the Ruby Marshal magic (04 08)" },
  { format: "Python (pickle)", rx: /gA[JNQU][A-Za-z0-9+/=]{12,}/, note: "base64 of a Python pickle protocol opcode (80 0x)" },
];

// A JWT (three base64url segments) is legitimate and not a deserialization sink.
const JWT_RE = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;

function decodeOnce(value: string): string {
  try { return decodeURIComponent(value); } catch { return value; }
}

/**
 * Inspect a page's Set-Cookie headers for a serialized object. Returns finding
 * partials (no id) so the caller can wrap them with its own `vuln()` builder.
 * `seen` de-duplicates a cookie name+format already reported elsewhere in the scan.
 */
export function detectSerializedCookies(
  setCookies: string[],
  pageUrl: string,
  seen: Set<string>,
): Omit<ScanVulnerability, "id">[] {
  const out: Omit<ScanVulnerability, "id">[] = [];

  for (const cookie of setCookies || []) {
    const first = (cookie || "").split(";")[0] ?? "";
    const eq = first.indexOf("=");
    if (eq <= 0) continue;
    const name = first.slice(0, eq).trim();
    const rawVal = first.slice(eq + 1).trim();
    if (!name || rawVal.length < 12) continue;

    for (const val of [rawVal, decodeOnce(rawVal)]) {
      if (JWT_RE.test(val)) continue;
      let matched = false;
      for (const m of MARKERS) {
        const hit = m.rx.exec(val);
        if (!hit) continue;
        const key = `deser::${name}::${m.format}`;
        if (seen.has(key)) { matched = true; break; }
        seen.add(key);
        const sample = hit[0].slice(0, 24); // format header only — not the payload/secret
        out.push({
          name: `Insecure Deserialization Exposure (${m.format} object in cookie "${name}")`,
          severity: "high",
          category: "Insecure Deserialization",
          description:
            `The cookie "${name}" carries a ${m.format} serialized object. Because the client returns this cookie on every request, the server deserializes an attacker-modifiable value — the root condition for insecure deserialization (CWE-502), which frequently escalates to remote code execution through a gadget chain. SecScan detects the exposure and does not attempt exploitation.`,
          evidence: `GET ${pageUrl}\nSet-Cookie: ${name}=${sample}… (value redacted)\nSignature: ${m.note}`,
          solution:
            `Do not deserialize native ${m.format} objects from client-supplied data. Store only an opaque server-side session id in the cookie (object held server-side), or use JSON with strict schema validation and an HMAC signature so a tampered value is rejected before deserialization.`,
          cweId: "CWE-502",
          cvssScore: 8.1,
          wstgId: "WSTG-BUSL-06",
          confidence: 85,
        });
        matched = true;
        break; // one format per cookie
      }
      if (matched) break; // don't double-report the decoded variant
    }
  }
  return out;
}
