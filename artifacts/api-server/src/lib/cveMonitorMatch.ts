/** Matching NVD CVEs to a site's detected technologies and versions. */
/** One vulnerable-product entry from a CVE's configurations. */
export interface CpeRange {
  /** "vendor:product", e.g. "f5:nginx". */
  product: string;
  /** Exact version from the CPE, when the entry names one ("1.18.0"); null for "*" or "-". */
  exactVersion: string | null;
  startIncluding?: string;
  startExcluding?: string;
  endIncluding?: string;
  endExcluding?: string;
}

export interface NvdCve {
  id: string;
  description: string;
  severity: string;
  cvssScore: number | null;
  publishedDate: string;
  /** NVD's workflow status: Analyzed, Modified, Awaiting Analysis, Rejected… */
  status: string;
  /** Vulnerable products only; empty until NVD has analysed the CVE. */
  products: CpeRange[];
}

/**
 * Technology name as the fingerprinter emits it (techFingerprint.ts / scanner.ts)
 * → the NVD vendor:product pairs for that software. Every pair was checked
 * against NVD's CPE dictionary on 2026-09-24. Software sometimes appears under
 * more than one vendor after a transfer (nginx: nginx:nginx, then f5:nginx).
 */
export const TECH_CPE: Record<string, string[]> = {
  // Web servers and proxies
  "Nginx":          ["f5:nginx", "nginx:nginx"],
  "Apache":         ["apache:http_server"],
  "OpenResty":      ["openresty:openresty"],
  "IIS":            ["microsoft:internet_information_services"],
  "LiteSpeed":      ["litespeedtech:litespeed_web_server", "litespeedtech:openlitespeed"],
  "Caddy":          ["caddyserver:caddy"],
  "Varnish Cache":  ["varnish-cache:varnish_cache"],
  "Squid Proxy":    ["squid-cache:squid"],
  "Envoy Proxy":    ["envoyproxy:envoy"],
  "Gunicorn":       ["gunicorn:gunicorn"],
  "Tomcat":         ["apache:tomcat"],
  "OpenSSL":        ["openssl:openssl"],
  // Languages and runtimes
  "PHP":            ["php:php"],
  "Python":         ["python:python"],
  "Node.js":        ["nodejs:node.js"],
  "Kestrel (.NET)": ["microsoft:asp.net_core"],
  "ASP.NET":        ["microsoft:asp.net_core", "microsoft:asp.net"],
  // Frameworks
  "Django":         ["djangoproject:django"],
  "Ruby on Rails":  ["rubyonrails:rails", "rubyonrails:ruby_on_rails"],
  "Laravel":        ["laravel:framework", "laravel:laravel"],
  "Express.js":     ["expressjs:express", "openjsf:express"],
  "Spring":         ["vmware:spring_framework", "pivotal_software:spring_framework"],
  "Next.js":        ["vercel:next.js", "zeit:next.js"],
  "Nuxt.js":        ["nuxt:nuxt", "nuxtjs:nuxt.js"],
  "Gatsby":         ["gatsbyjs:gatsby"],
  // Front-end libraries (only matched when the scan read a version)
  "Angular":        ["angular:angular", "angularjs:angular.js"],
  "React":          ["facebook:react"],
  "Ember.js":       ["emberjs:ember.js"],
  "jQuery":         ["jquery:jquery"],
  "Lodash":         ["lodash:lodash"],
  "Bootstrap":      ["getbootstrap:bootstrap"],
  // CMS and commerce
  "WordPress":      ["wordpress:wordpress"],
  "Drupal":         ["drupal:drupal"],
  // NVD writes the "!" in Joomla's product name escaped, as it appears here.
  "Joomla":         ["joomla:joomla\\!"],
  "Ghost":          ["ghost:ghost"],
  "Magento":        ["magento:magento", "adobe:magento", "adobe:commerce"],
  "WooCommerce":    ["woocommerce:woocommerce", "automattic:woocommerce"],
  // Not listed, because NVD has no product entry to match against (checked):
  // Vue.js, Svelte, Remix, htmx, Alpine.js, Backbone.js. Hosting and SaaS
  // platforms are left out on purpose; see the file header.
};

/** What a match is based on, carried into the alert so it is never overstated. */
export type MatchBasis = "affected" | "unconfirmed";

export interface CveMatch {
  cve: NvdCve;
  /** The technology as detected, version included ("Nginx 1.18.0"). */
  matchedTech: string;
  basis: MatchBasis;
}

// ─── Versions ────────────────────────────────────────────────────────────────

/**
 * The bare technology name, with any trailing version removed.
 *
 * scanner.ts appends versions for display ("Nginx" → "Nginx 1.18.0") while the
 * table is keyed on the bare name. Only a trailing version-shaped token is
 * stripped: splitting on the first space would break "Ruby on Rails".
 */
export function bareTechName(tech: string): string {
  return tech.replace(/\s+v?\d[\w.-]*$/i, "").trim();
}

/** The version the scanner detected, if the name carries one ("Nginx 1.18.0" → "1.18.0"). */
export function detectedVersion(tech: string): string | null {
  const m = /\s+v?(\d[\w.-]*)$/i.exec(tech.trim());
  return m ? m[1]! : null;
}

/**
 * Compare two dotted versions numerically: 1.9 < 1.10, 1.19.3.2 > 1.19.3.
 * A trailing distro or build suffix ("1.18.0-1ubuntu", "8.1.2p1") is ignored,
 * because the upstream number is what NVD's ranges are written in.
 * Returns negative, zero or positive, like a sort comparator.
 */
export function compareVersions(a: string, b: string): number {
  const nums = (v: string) =>
    v
      .replace(/^v/i, "")
      .split(/[-+~_ ]/)[0]!
      .split(".")
      .map((part) => {
        const n = /^\d+/.exec(part);
        return n ? parseInt(n[0], 10) : 0;
      });
  const x = nums(a);
  const y = nums(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** Whether a detected version falls inside one vulnerable-product entry. */
export function versionInRange(version: string, r: CpeRange): boolean {
  if (r.exactVersion) return compareVersions(version, r.exactVersion) === 0;
  const hasRange = r.startIncluding || r.startExcluding || r.endIncluding || r.endExcluding;
  // "*" with no range means every version, which NVD uses for products whose
  // affected versions it could not bound. Treated as affected.
  if (!hasRange) return true;
  if (r.startIncluding && compareVersions(version, r.startIncluding) < 0) return false;
  if (r.startExcluding && compareVersions(version, r.startExcluding) <= 0) return false;
  if (r.endIncluding && compareVersions(version, r.endIncluding) > 0) return false;
  if (r.endExcluding && compareVersions(version, r.endExcluding) >= 0) return false;
  return true;
}

// ─── Matching ────────────────────────────────────────────────────────────────

export const SERIOUS = new Set(["CRITICAL", "HIGH"]);

/**
 * The CVEs that affect the detected software, each with the basis for saying so.
 *
 * No description matching of any kind: a CVE matches only when its structured
 * product data names the software. See the file header for the rules.
 */
export function matchCvesToTechnologies(technologies: string[], cves: NvdCve[]): CveMatch[] {
  const results: CveMatch[] = [];

  for (const tech of technologies) {
    const products = TECH_CPE[bareTechName(tech)];
    if (!products || products.length === 0) continue;
    const version = detectedVersion(tech);

    for (const cve of cves) {
      if (cve.status.toLowerCase() === "rejected") continue;
      const entries = cve.products.filter((p) => products.includes(p.product));
      if (entries.length === 0) continue;

      let basis: MatchBasis | null;
      if (version) {
        basis = entries.some((e) => versionInRange(version, e)) ? "affected" : null;
      } else {
        // Without a version this is "the product has a new vulnerability", which is
        // only worth an interruption when it is serious.
        basis = SERIOUS.has(cve.severity.toUpperCase()) ? "unconfirmed" : null;
      }
      if (!basis) continue;

      if (!results.some((r) => r.cve.id === cve.id && r.matchedTech === tech)) {
        results.push({ cve, matchedTech: tech, basis });
      }
    }
  }

  return results;
}

/**
 * How a match is described wherever a person reads it (the alert row, the email,
 * the webhook). The two bases must never read the same.
 */
export function describeAffected(match: Pick<CveMatch, "matchedTech" | "basis">): string {
  return match.basis === "affected"
    ? `${match.matchedTech} (detected version is in the affected range)`
    : `${bareTechName(match.matchedTech)} (version not detected; check whether yours is affected)`;
}
