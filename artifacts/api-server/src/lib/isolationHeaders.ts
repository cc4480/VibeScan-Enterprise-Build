/**
 * The three cross-origin isolation headers (COOP / COEP / CORP).
 *
 * Kept apart from scanner.ts so the checks can be tested directly. All three are INFO: absence
 * is only a problem for a page that uses SharedArrayBuffer or high-resolution timers.
 *
 * CWE-16 (Configuration), the same one the other general hardening headers carry, not CWE-346
 * ("Origin Validation Error"): these headers do not validate anything, and CWE-346 maps to ASVS
 * V14.5.3 "Origin validated on cross-origin requests", so a missing COEP showed up in the
 * compliance panel as evidence about origin validation.
 */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

function headerVal(headers: Record<string, string>, name: string): string | undefined {
  const lower = name.toLowerCase();
  const key = Object.keys(headers).find((k) => k.toLowerCase() === lower);
  return key ? headers[key] : undefined;
}

export function checkIsolationHeaders(rawHeaders: Record<string, string>, finalUrl: string): ScanVulnerability[] {
  const out: ScanVulnerability[] = [];
  // ── Cross-Origin isolation headers (COOP / COEP / CORP) ─────────────
  // These headers enable cross-origin isolation, which is required to safely
  // use SharedArrayBuffer and high-resolution timers. Most public-facing web
  // apps don't use these APIs and don't need full isolation — absence is
  // therefore informational, not a direct vulnerability. Flag as INFO so
  // teams can make an informed choice rather than reflexively chasing headers.
  const coop = headerVal(rawHeaders, "cross-origin-opener-policy");
  if (!coop) {
    out.push(vuln({
      name: "Missing Cross-Origin-Opener-Policy (COOP)",
      severity: "info",
      category: "Browser Feature Control",
      description: "The Cross-Origin-Opener-Policy header is not set. COOP isolates your browsing context from cross-origin popups, preventing other pages from accessing your window object. It is required to safely enable SharedArrayBuffer and high-resolution timers. Most public web apps do not need these APIs, so absence is typically informational — but enabling COOP is a free defence-in-depth measure.",
      evidence: `GET ${finalUrl}\nCross-Origin-Opener-Policy: (header absent from response)`,
      solution: "Add: Cross-Origin-Opener-Policy: same-origin (most secure) or same-origin-allow-popups if you need cross-origin popup interaction. Only required if you use SharedArrayBuffer or high-resolution timers.",
      cweId: "CWE-16",
      wstgId: "WSTG-CONF-07",
    }));
  }

  const coep = headerVal(rawHeaders, "cross-origin-embedder-policy");
  if (!coep) {
    out.push(vuln({
      name: "Missing Cross-Origin-Embedder-Policy (COEP)",
      severity: "info",
      category: "Browser Feature Control",
      description: "The Cross-Origin-Embedder-Policy header is not set. COEP (require-corp) prevents the page from loading cross-origin resources unless they explicitly opt in. It is required alongside COOP to achieve cross-origin isolation. Absence is informational for most sites — only needed if your app uses SharedArrayBuffer or high-resolution performance timers.",
      evidence: `GET ${finalUrl}\nCross-Origin-Embedder-Policy: (header absent from response)`,
      solution: "Add: Cross-Origin-Embedder-Policy: require-corp. Note: this requires all subresources to serve a CORP or CORS header. Use credentialless if require-corp causes third-party resource breakage.",
      cweId: "CWE-16",
      wstgId: "WSTG-CONF-07",
    }));
  }

  const corp = headerVal(rawHeaders, "cross-origin-resource-policy");
  if (!corp) {
    out.push(vuln({
      name: "Missing Cross-Origin-Resource-Policy (CORP)",
      severity: "info",
      category: "Browser Feature Control",
      description: "The Cross-Origin-Resource-Policy header is absent. Without CORP, other origins can include this resource in their pages (via <img>, <script>, etc.). In cross-origin isolated contexts this could expose content to Spectre-class timing attacks. For most public resources this is informational — but adding CORP: same-origin or same-site is a low-effort hardening step.",
      evidence: `GET ${finalUrl}\nCross-Origin-Resource-Policy: (header absent from response)`,
      solution: "Add: Cross-Origin-Resource-Policy: same-origin (for same-site-only resources) or same-site. Use cross-origin only for truly public resources.",
      cweId: "CWE-16",
      wstgId: "WSTG-CONF-07",
    }));
  }

  return out;
}
