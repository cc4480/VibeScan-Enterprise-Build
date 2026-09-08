/**
 * Structured data, social preview metadata, and indexability.
 *
 * Two things live here, deliberately kept apart by severity.
 *
 * The first is a genuine security surface. Structured data is generated from a
 * CMS or a build step and routinely carries more than its author realised —
 * internal hostnames, staging URLs, RFC 1918 addresses — into a document served
 * to the whole internet. A canonical tag pointing at a domain the operator does
 * not own is a classic symptom of an SEO-spam injection, and a social preview
 * image loaded over http:// on an https:// page is plain mixed content. Those
 * get real severities.
 *
 * The second is presentation quality: missing Open Graph tags, absent Twitter
 * Card metadata, JSON-LD that does not parse. Useful in a site report, not
 * security. Everything in that group is INFO, which contributes 0 to the risk
 * score (see computeRiskScore) — a site with no og:image must never be graded
 * as less secure than one with it. Getting this wrong would make the grade mean
 * something other than security, which is the whole product.
 *
 * Parsing is regex-based, matching the rest of the scanner. There is no DOM
 * library in this package and adding one to read a handful of tags would be a
 * poor trade.
 */
import { randomUUID } from "node:crypto";
import { detectChallengePage } from "./challengePage.js";
import type { ScanVulnerability } from "./scanner.js";

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

/** Cap on how much of a document is scanned for tags. */
const MAX_HTML_BYTES = 512_000;
/** Cap on a single JSON-LD block, so a pathological document cannot stall a scan. */
const MAX_JSONLD_BYTES = 200_000;

export interface JsonLdBlock {
  raw: string;
  /** Parsed value, or null when the block is not valid JSON. */
  value: unknown;
  parseError: string | null;
}

export interface PageMetadata {
  /** Lowercased meta name/property → content, first occurrence wins. */
  meta: Map<string, string>;
  canonical: string | null;
  jsonLd: JsonLdBlock[];
  title: string | null;
}

// ── extraction ─────────────────────────────────────────────────────────────

function decodeEntities(s: string): string {
  return s
    .replace(/&quot;/gi, '"')
    .replace(/&#0*39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&amp;/gi, "&");
}

/**
 * Pull the content of a tag attribute.
 *
 * Handles single, double and unquoted values because real documents use all
 * three, and a check that only reads double-quoted attributes silently sees
 * nothing on the sites that need it most.
 */
function attr(tag: string, name: string): string | null {
  const re = new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s"'>]+))`, "i");
  const m = re.exec(tag);
  if (!m) return null;
  return decodeEntities(m[2] ?? m[3] ?? m[4] ?? "").trim();
}

export function extractPageMetadata(html: string): PageMetadata {
  const doc = html.slice(0, MAX_HTML_BYTES);
  const meta = new Map<string, string>();

  for (const m of doc.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = m[0];
    // property= is the Open Graph spelling, name= the HTML one. Twitter Cards
    // appear under both in the wild, so neither can be assumed.
    const key = (attr(tag, "property") ?? attr(tag, "name"))?.toLowerCase();
    const content = attr(tag, "content");
    if (!key || content === null) continue;
    if (!meta.has(key)) meta.set(key, content);
  }

  let canonical: string | null = null;
  for (const m of doc.matchAll(/<link\b[^>]*>/gi)) {
    const rel = attr(m[0], "rel")?.toLowerCase();
    if (rel === "canonical") {
      canonical = attr(m[0], "href");
      break;
    }
  }

  const jsonLd: JsonLdBlock[] = [];
  for (const m of doc.matchAll(
    /<script\b[^>]*\btype\s*=\s*["']?application\/ld\+json["']?[^>]*>([\s\S]*?)<\/script\s*>/gi,
  )) {
    const raw = (m[1] ?? "").trim();
    if (!raw) {
      jsonLd.push({ raw, value: null, parseError: "empty block" });
      continue;
    }
    if (raw.length > MAX_JSONLD_BYTES) {
      // Too large to parse safely; record it without claiming it is malformed.
      jsonLd.push({ raw: raw.slice(0, 200), value: null, parseError: null });
      continue;
    }
    try {
      jsonLd.push({ raw, value: JSON.parse(raw), parseError: null });
    } catch (err) {
      jsonLd.push({ raw, value: null, parseError: (err as Error).message.slice(0, 120) });
    }
  }

  const titleMatch = /<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(doc);
  const title = titleMatch ? decodeEntities(titleMatch[1] ?? "").trim() : null;

  return { meta, canonical, jsonLd, title };
}

// ── internal-host detection ────────────────────────────────────────────────

/**
 * Hostnames and addresses that should never appear in a public document.
 *
 * Deliberately narrow. Anything ambiguous — a hostname that merely looks
 * internal, a private-looking path — is left alone; the value of this check
 * depends entirely on it not crying wolf.
 */
const INTERNAL_HOST = new RegExp(
  [
    "localhost",
    "\\b127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b",
    "\\b10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b",
    "\\b192\\.168\\.\\d{1,3}\\.\\d{1,3}\\b",
    "\\b172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}\\b",
    "\\b[a-z0-9-]+\\.(?:local|internal|lan|intranet|corp|test|localdomain)\\b",
  ].join("|"),
  "i",
);

/** Collect every string value in a JSON-LD document, however deeply nested. */
function collectStrings(value: unknown, out: string[], depth = 0): void {
  if (depth > 12 || out.length > 2000) return;
  if (typeof value === "string") {
    out.push(value);
  } else if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out, depth + 1);
  } else if (value && typeof value === "object") {
    for (const v of Object.values(value as Record<string, unknown>)) {
      collectStrings(v, out, depth + 1);
    }
  }
}

// ── host comparison ────────────────────────────────────────────────────────

/**
 * Is `other` the same site as `base`, allowing for www/subdomain differences?
 *
 * Compares by suffix rather than by computing a registrable domain. An eTLD+1
 * calculation needs the public-suffix list to be right about co.uk, com.au and
 * a few thousand others, and being wrong there produces a HIGH-visibility false
 * positive on exactly the international sites least able to dismiss it. Suffix
 * matching cannot make that mistake: www.example.com and example.com match,
 * example.com and evil.com do not.
 */
function sameSite(base: string, other: string): boolean {
  const a = base.toLowerCase().replace(/\.$/, "");
  const b = other.toLowerCase().replace(/\.$/, "");
  if (a === b) return true;
  return a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

// ── findings ───────────────────────────────────────────────────────────────

const OG_REQUIRED = ["og:title", "og:description", "og:image"] as const;

/**
 * Build findings from a page's metadata.
 *
 * `pageUrl` is the FINAL url after redirects — comparing a canonical tag
 * against the URL originally requested would flag every site that redirects
 * apex to www.
 *
 * Pass `status` and `headers` wherever they are available. Without them a WAF
 * challenge cannot be recognised, and every finding here would then describe
 * the interstitial instead of the site.
 */
export function structuredDataFindings(
  pageUrl: string,
  html: string,
  opts: { status?: number; headers?: Record<string, string> } = {},
): ScanVulnerability[] {
  const findings: ScanVulnerability[] = [];

  /*
   * A challenge page invalidates EVERYTHING here, not merely the presentation
   * checks. Its canonical tag, its structured data and its preview images all
   * belong to the vendor. stackoverflow.com and npmjs.com were both reported as
   * having no Open Graph metadata and as being excluded from search indexes —
   * all four statements true of Cloudflare's interstitial and none of them true
   * of those sites. The scanner reports the interception separately, so nothing
   * is hidden by returning early.
   */
  if (detectChallengePage(opts.status ?? 200, html, opts.headers ?? {}).isChallenge) {
    return findings;
  }

  const md = extractPageMetadata(html);

  let page: URL;
  try {
    page = new URL(pageUrl);
  } catch {
    return findings;
  }
  const isHttps = page.protocol === "https:";

  // ── security-relevant ────────────────────────────────────────────────────

  // Internal hosts leaked through structured data.
  const leaked = new Set<string>();
  for (const block of md.jsonLd) {
    const strings: string[] = [];
    collectStrings(block.value, strings);
    for (const s of strings) {
      const hit = INTERNAL_HOST.exec(s);
      if (hit) leaked.add(s.slice(0, 160));
    }
  }
  if (leaked.size > 0) {
    findings.push(vuln({
      name: "Internal Hostname Exposed in Structured Data",
      severity: "low",
      category: "Information Disclosure",
      description:
        "JSON-LD structured data on this page contains hostnames or private IP addresses that are only meaningful inside the operator's network. Structured data is generated from a CMS or build pipeline and is easy to overlook, but it is served to every visitor and indexed by search engines, so these values map internal infrastructure for anyone reading the page source.",
      evidence: [...leaked].slice(0, 5).map((s) => `JSON-LD value: ${s}`).join("\n"),
      solution:
        "Configure the site's canonical/base URL in the CMS or build so structured data is generated with public hostnames, and re-generate the affected pages. Check staging-to-production promotion for the same leak.",
      cweId: "CWE-200",
      cvssScore: 3.7,
      wstgId: "WSTG-INFO-05",
      confidence: 88,
    }));
  }

  // Social preview assets fetched over cleartext from an encrypted page.
  const insecureAssets = ["og:image", "og:image:secure_url", "twitter:image", "og:video"]
    .map((k) => [k, md.meta.get(k)] as const)
    .filter((pair): pair is readonly [string, string] =>
      typeof pair[1] === "string" && /^http:\/\//i.test(pair[1]));
  if (isHttps && insecureAssets.length > 0) {
    findings.push(vuln({
      name: "Social Preview Asset Referenced Over HTTP",
      severity: "low",
      category: "Transport Security",
      description:
        "This page is served over HTTPS but points its social preview metadata at cleartext http:// URLs. Anyone on the network path can substitute the image or video used when the page is shared, and some crawlers refuse the mixed reference outright, so the preview silently breaks.",
      evidence: insecureAssets.map(([k, v]) => `<meta property="${k}" content="${v}">`).join("\n"),
      solution: "Serve preview assets over HTTPS and update the og:/twitter: tags to https:// URLs.",
      cweId: "CWE-311",
      cvssScore: 3.1,
      wstgId: "WSTG-CRYP-03",
      confidence: 90,
    }));
  }

  // A canonical tag handing ranking authority to a domain that is not this one.
  if (md.canonical) {
    let canonicalUrl: URL | null = null;
    try {
      canonicalUrl = new URL(md.canonical, page);
    } catch {
      canonicalUrl = null;
    }
    if (canonicalUrl && !sameSite(page.hostname, canonicalUrl.hostname)) {
      findings.push(vuln({
        name: "Canonical URL Points to an External Domain",
        severity: "low",
        category: "Information Disclosure",
        description:
          `The canonical link on this page names ${canonicalUrl.hostname}, a different site from ${page.hostname}. Search engines treat that as an instruction to credit the other domain and drop this page from results. It is legitimate for syndicated content, and a well-known symptom of SEO-spam injection when it is not — a compromise that is invisible in the rendered page and typically found only when traffic disappears.`,
        evidence: `<link rel="canonical" href="${md.canonical}">\nPage: ${page.href}`,
        solution:
          "Confirm the external canonical is intentional. If it is not, treat the page as compromised: audit the CMS templates, plugins and any injected content for the source of the tag before simply removing it.",
        cweId: "CWE-200",
        cvssScore: 3.1,
        wstgId: "WSTG-CONF-04",
        confidence: 80,
      }));
    }
  }

  // ── presentation quality (INFO — never affects the security grade) ───────

  const malformed = md.jsonLd.filter((b) => b.parseError);
  if (malformed.length > 0) {
    findings.push(vuln({
      name: "Malformed JSON-LD Structured Data",
      severity: "info",
      category: "Structured Data",
      description:
        `${malformed.length} of ${md.jsonLd.length} JSON-LD block(s) on this page are not valid JSON. Search engines discard invalid structured data without reporting an error, so the rich results the markup was added for never appear and nothing indicates why.`,
      evidence: malformed
        .slice(0, 3)
        .map((b) => `${b.parseError}\n  near: ${b.raw.slice(0, 120)}`)
        .join("\n"),
      solution:
        "Validate the block with Google's Rich Results Test or schema.org's validator. Trailing commas and unescaped quotes inside string values are the usual causes when the markup is templated.",
      cvssScore: 0,
      confidence: 95,
    }));
  }

  // Blocks that parse but carry no schema.org typing do nothing at all.
  const untyped = md.jsonLd.filter((b) => {
    if (b.parseError || b.value === null) return false;
    const objs = Array.isArray(b.value) ? b.value : [b.value];
    return objs.some((o) => {
      if (!o || typeof o !== "object") return true;
      const rec = o as Record<string, unknown>;
      // @graph carries its own typed nodes, so the wrapper needs no @type.
      if ("@graph" in rec) return false;
      return !("@type" in rec) || !("@context" in rec);
    });
  });
  if (untyped.length > 0) {
    findings.push(vuln({
      name: "Structured Data Missing @context or @type",
      severity: "info",
      category: "Structured Data",
      description:
        "One or more JSON-LD blocks parse as valid JSON but omit @context or @type. Without both, the markup is not schema.org data and is ignored — the page appears to have structured data while getting none of the benefit.",
      evidence: untyped.slice(0, 3).map((b) => b.raw.slice(0, 160)).join("\n"),
      solution:
        'Add "@context": "https://schema.org" and an appropriate "@type" to each block, or nest the typed nodes under "@graph".',
      cvssScore: 0,
      confidence: 92,
    }));
  }

  if (md.jsonLd.length === 0 && !md.meta.has("og:type")) {
    findings.push(vuln({
      name: "No Structured Data Found",
      severity: "info",
      category: "Structured Data",
      description:
        "The page publishes no schema.org structured data. This has no security impact — it is reported because structured data is what drives rich results, and its absence on a public marketing or content page is usually an oversight rather than a decision.",
      evidence: `No <script type="application/ld+json"> blocks in ${page.href}`,
      solution:
        "Add JSON-LD for the types that describe the page — Organization and WebSite on the homepage, Article, Product or FAQPage on content pages.",
      cvssScore: 0,
      confidence: 95,
    }));
  }

  const missingOg = OG_REQUIRED.filter((k) => !md.meta.get(k));
  if (missingOg.length > 0) {
    findings.push(vuln({
      name: "Incomplete Open Graph Metadata",
      severity: "info",
      category: "Structured Data",
      description:
        `Open Graph tags missing: ${missingOg.join(", ")}. Links to this page shared in Slack, iMessage, LinkedIn or Facebook fall back to whatever those clients can scrape, which is typically the bare URL and no image.`,
      evidence: OG_REQUIRED.map((k) => `${k}: ${md.meta.get(k) ?? "(absent)"}`).join("\n"),
      solution:
        "Add og:title, og:description and og:image (absolute https:// URL, at least 1200×630) to the document head.",
      cvssScore: 0,
      confidence: 95,
    }));
  }

  if (!md.meta.has("twitter:card") && md.meta.has("og:title")) {
    // Only worth mentioning where the rest of the social metadata exists —
    // otherwise it is the same omission reported twice.
    findings.push(vuln({
      name: "Twitter Card Metadata Absent",
      severity: "info",
      category: "Structured Data",
      description:
        "The page has Open Graph tags but no twitter:card, so X/Twitter renders a plain link rather than the summary card the Open Graph tags were added to produce.",
      evidence: "twitter:card: (absent)",
      solution: 'Add <meta name="twitter:card" content="summary_large_image">.',
      cvssScore: 0,
      confidence: 90,
    }));
  }

  const robots = md.meta.get("robots") ?? "";
  if (/\bnoindex\b/i.test(robots)) {
    findings.push(vuln({
      name: "Page Excluded From Search Indexes",
      severity: "info",
      category: "Structured Data",
      description:
        "A robots meta tag on this page requests noindex, so search engines will not list it. That is correct for a staging or gated page and an expensive accident on a production one — it is a common leftover from a pre-launch configuration.",
      evidence: `<meta name="robots" content="${robots}">`,
      solution: "If the page is meant to be found, remove noindex and request re-indexing in Search Console.",
      cvssScore: 0,
      confidence: 95,
    }));
  }

  return findings;
}
