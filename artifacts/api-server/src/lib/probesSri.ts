/** Subresource Integrity probe: external scripts and stylesheets loaded without an integrity hash. */
import { expectsIntegrity, isVendorUpdated } from "./sriPolicy";
import type { ScanVulnerability } from "./scanner";
import { vuln } from "./probesCore";
import { compromisedScriptFindings } from "./compromisedScriptHosts";

const PIN_ADVICE =
  'Add integrity and crossorigin to all external resources: `<script src="https://cdn.example.com/lib.js" integrity="sha384-..." crossorigin="anonymous">`. Generate hashes at https://www.srihash.org/ or using `openssl dgst -sha384 -binary FILE | openssl base64 -A`.';

// For tags the provider edits in place. A hash pins one version, so the next vendor update would fail it
// and the tag would silently stop working; pinning is not the advice to give.
const VENDOR_ADVICE =
  "These tags are edited by their vendor under a fixed URL, so an integrity hash would break them at the next update. Either self-host a pinned copy and update it on your own schedule, or accept that the vendor can run code on the page and limit the damage: restrict script-src in your Content-Security-Policy to the hosts you use, load the tag only on the pages that need it, and keep it off login, payment and account pages.";

/** The subresource-integrity probe, plus the script hosts tied to a known supply-chain attack (compromisedScriptHosts.ts). */
export async function checkSRI(html: string, baseUrl: string, requestedUrl?: string): Promise<ScanVulnerability[]> {
  return [...compromisedScriptFindings(html, baseUrl, requestedUrl ?? baseUrl), ...(await sriFindings(html, baseUrl, requestedUrl))];
}

async function sriFindings(html: string, baseUrl: string, requestedUrl?: string): Promise<ScanVulnerability[]> {
  let baseHost: string;
  try {
    baseHost = new URL(baseUrl).hostname;
  } catch {
    return [];
  }
  // The address the user asked for is the site's too, even if it redirected to another domain.
  let requestedHost: string | null = null;
  try {
    if (requestedUrl) requestedHost = new URL(requestedUrl).hostname;
  } catch { /* ignore an unparseable request address */ }

  const scriptRegex = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
  const linkRegex = /<link[^>]+href=["']([^"']+)["'][^>]*rel=["']stylesheet["'][^>]*>/gi;
  const pinnable: string[] = [];
  const vendorUpdated: string[] = [];

  const checkTag = (tag: string, src: string) => {
    try {
      const u = new URL(src, baseUrl);
      // Third-party only, and not a provider that updates the script in place (lib/sriPolicy.ts):
      // the site's own CDN needs no SRI, and SRI on Stripe.js or Tag Manager breaks them.
      if (expectsIntegrity(baseHost, u, requestedHost ? [requestedHost] : []) && !tag.includes("integrity=")) {
        // Skip resources whose URL pathname contains a long hex content hash.
        // Content-addressed URLs (e.g. webpack chunks: "/chunk.a1b2c3d4e5f6a7b8.js")
        // are effectively pinned by the hash in the filename — SRI is redundant
        // because changing the file content would change the URL, not silently
        // serve a tampered version. Flagging these would be a false positive.
        const hasContentHash = /[a-f0-9]{16,}/i.test(u.pathname);
        if (!hasContentHash) (isVendorUpdated(u) ? vendorUpdated : pinnable).push(src);
      }
    } catch { /* relative URL */ }
  };

  let m: RegExpExecArray | null;
  while ((m = scriptRegex.exec(html)) !== null) checkTag(m[0], m[1]);
  while ((m = linkRegex.exec(html)) !== null) checkTag(m[0], m[1]);

  const total = pinnable.length + vendorUpdated.length;
  if (total === 0) return [];

  const line = (s: string) => `<script/link src="${s}" (no integrity= attribute)>`;
  const evidence = [
    ...pinnable.slice(0, 5).map(line),
    ...vendorUpdated.slice(0, pinnable.length ? 3 : 5).map((s) => `${line(s)} [vendor-updated tag]`),
  ].join("\n");
  const solution = !vendorUpdated.length
    ? PIN_ADVICE
    : !pinnable.length
      ? VENDOR_ADVICE
      : `${PIN_ADVICE}\n\nFor the tags marked [vendor-updated tag]: ${VENDOR_ADVICE}`;

  return [vuln({
    name: "External Resources Missing Subresource Integrity (SRI)",
    severity: "medium",
    category: "Supply Chain Security",
    description: `${total} external script(s)/stylesheet(s) are loaded from third-party CDNs without Subresource Integrity hashes. If any of these CDNs are compromised (which has happened to major CDNs), attackers can inject arbitrary JavaScript that runs on your site for all visitors—stealing credentials, hijacking sessions, or installing skimmers.`,
    evidence,
    solution,
    cweId: "CWE-353",
    cvssScore: 6.1,
    wstgId: "WSTG-CONF-04",
  })];
}
