/** Technology and version extraction from headers and HTML. */
import { isDistroPackaged } from "./bannerRules";
import { type DetectedVersion, VERSION_PATTERNS } from "./cve-patterns";

/**
 * What a page actually loads or runs, which is the only place a library version can be read from.
 *
 * The patterns used to run over the whole document, so a changelog sentence ("we removed
 * jquery-1.12.4"), a tutorial's install snippet shown as escaped text (&lt;script src=…&gt;) or a
 * download link to an old release each produced a known-CVE finding for a library the page does not
 * run. URLs now come only from real <script src> and <link href> tags (a literal "<" before the tag
 * name is what separates a tag from its escaped rendering) and import maps. Banners and runtime
 * version properties come only from executable inline <script> and <style> bodies; data blocks
 * (JSON, templates) are skipped because a framework's page-state JSON carries the page's prose.
 */
export interface VersionEvidence {
  /** <script src>, <link rel=modulepreload | preload as=script>, import-map entries. */
  scriptUrls: string[];
  /** Every other <link href>: stylesheets, icons and the like. */
  otherUrls: string[];
  inlineScripts: string[];
  inlineStyles: string[];
  /** Raw <meta> tags naming a generator (CMS version disclosure). */
  generatorMeta: string[];
}

function attributes(tag: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  for (const a of tag.matchAll(/([^\s=/<>]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g)) {
    attrs[a[1]!.toLowerCase()] = a[2] ?? a[3] ?? a[4] ?? "";
  }
  return attrs;
}

export function versionEvidence(html: string): VersionEvidence {
  // Strip comments before cutting to 150KB, so a comment that straddles the cut is removed whole
  // rather than left open with its markup exposed to the scanners below.
  const doc = html.replace(/<!--[\s\S]*?-->/g, "").slice(0, 150_000);
  const ev: VersionEvidence = { scriptUrls: [], otherUrls: [], inlineScripts: [], inlineStyles: [], generatorMeta: [] };

  for (const m of doc.matchAll(/<(script|link)\b[^>]*>/gi)) {
    const attrs = attributes(m[0]);
    if (m[1]!.toLowerCase() === "script") {
      if (attrs.src) ev.scriptUrls.push(attrs.src);
      continue;
    }
    if (!attrs.href) continue;
    const rel = (attrs.rel ?? "").toLowerCase();
    const loadsScript = /\bmodulepreload\b/.test(rel) || (/\bpreload\b/.test(rel) && (attrs.as ?? "").toLowerCase() === "script");
    (loadsScript ? ev.scriptUrls : ev.otherUrls).push(attrs.href);
  }

  for (const m of doc.matchAll(/<(script|style)\b([^>]*)>([\s\S]*?)<\/\1\s*>/gi)) {
    const body = m[3] ?? "";
    if (m[1]!.toLowerCase() === "style") {
      ev.inlineStyles.push(body);
      continue;
    }
    const attrs = attributes(m[2] ?? "");
    if (attrs.src) continue;
    const type = (attrs.type ?? "").trim().toLowerCase();
    if (type === "importmap") ev.scriptUrls.push(body);
    else if (!type || type === "module" || /^(?:text|application)\/(?:x-)?(?:java|ecma)script$/.test(type)) ev.inlineScripts.push(body);
  }

  for (const [tag] of doc.matchAll(/<meta\b[^>]*>/gi)) if (/generator/i.test(tag)) ev.generatorMeta.push(tag);
  return ev;
}

export function extractVersionedTechnologies(
  html: string,
  headers: Record<string, string>,
): DetectedVersion[] {
  const found: DetectedVersion[] = [];
  const seen = new Set<string>(); // avoid duplicates for same package

  const ev = versionEvidence(html);
  // Script URLs first, so a version on the script wins over one on a stylesheet.
  const urls = [...ev.scriptUrls, ...ev.otherUrls].join("\n");
  const inline = [...ev.inlineScripts, ...ev.inlineStyles, ...ev.generatorMeta].join("\n");

  for (const vp of VERSION_PATTERNS) {
    if (seen.has(vp.packageName)) continue;
    if (vp.scriptFile) {
      const runsScript =
        ev.scriptUrls.some((u) => vp.scriptFile!.test(u) || vp.patterns.some((rx) => rx.test(u))) ||
        ev.inlineScripts.some((s) => (vp.inlinePatterns ?? []).some((rx) => rx.test(s)));
      if (!runsScript) continue;
    }
    const attempts: Array<[RegExp, string]> = [
      ...vp.patterns.map((rx): [RegExp, string] => [rx, urls]),
      ...(vp.inlinePatterns ?? []).map((rx): [RegExp, string] => [rx, inline]),
    ];
    for (const [rx, content] of attempts) {
      const m = rx.exec(content);
      if (m?.[1]) {
        const version = m[1].replace(/^[vV]/, "");
        if (/^\d+\.\d+/.test(version)) {
          found.push({
            displayName: vp.displayName,
            techName: vp.techName ?? vp.displayName,
            packageName: vp.packageName,
            ecosystem: vp.ecosystem,
            version,
          });
          seen.add(vp.packageName);
          break;
        }
      }
    }
  }

  // ── Headers: extract versioned server/runtime software ────────────────────

  const serverHeader = Object.entries(headers).find(([k]) => k.toLowerCase() === "server")?.[1] ?? "";
  const poweredBy = Object.entries(headers).find(([k]) => k.toLowerCase() === "x-powered-by")?.[1] ?? "";

  // PHP version from X-Powered-By header (not in OSV, checked locally)
  const phpMatch = /PHP\/(\d+\.\d+\.?\d*)(\S*)/i.exec(poweredBy);
  if (phpMatch?.[1] && !seen.has("php")) {
    found.push({
      displayName: "PHP",
      techName: "PHP",
      packageName: "php",
      ecosystem: "local",
      version: phpMatch[1],
      distroPackaged: isDistroPackaged(phpMatch[2] ?? ""),
    });
    seen.add("php");
  }

  // Nginx version from Server header
  const nginxMatch = /nginx\/(\d+\.\d+\.\d+)(.*)/i.exec(serverHeader);
  if (nginxMatch?.[1] && !seen.has("nginx")) {
    found.push({ displayName: "Nginx", techName: "Nginx", packageName: "nginx", ecosystem: "local", version: nginxMatch[1], distroPackaged: isDistroPackaged(nginxMatch[2] ?? "") });
    seen.add("nginx");
  }

  // Apache version from Server header — techName matches detectTechnologies() output "Apache"
  const apacheMatch = /Apache\/(\d+\.\d+\.\d+)(.*)/i.exec(serverHeader);
  if (apacheMatch?.[1] && !seen.has("apache")) {
    found.push({ displayName: "Apache HTTPD", techName: "Apache", packageName: "apache", ecosystem: "local", version: apacheMatch[1], distroPackaged: isDistroPackaged(apacheMatch[2] ?? "") });
    seen.add("apache");
  }

  // Microsoft IIS version from Server header — techName matches detectTechnologies() output "IIS"
  const iisMatch = /Microsoft-IIS\/(\d+\.\d+)/i.exec(serverHeader);
  if (iisMatch?.[1] && !seen.has("iis")) {
    found.push({ displayName: "Microsoft IIS", techName: "IIS", packageName: "iis", ecosystem: "local", version: iisMatch[1] });
    seen.add("iis");
  }

  // OpenResty version from Server header
  const openrestyMatch = /openresty\/(\d+\.\d+\.\d+)/i.exec(serverHeader);
  if (openrestyMatch?.[1] && !seen.has("openresty")) {
    found.push({ displayName: "OpenResty", techName: "OpenResty", packageName: "openresty", ecosystem: "local", version: openrestyMatch[1] });
    seen.add("openresty");
  }

  // LiteSpeed version from Server header
  const litespeedMatch = /LiteSpeed\/(\d+\.\d+\.?\d*)/i.exec(serverHeader);
  if (litespeedMatch?.[1] && !seen.has("litespeed")) {
    found.push({ displayName: "LiteSpeed", techName: "LiteSpeed", packageName: "litespeed", ecosystem: "local", version: litespeedMatch[1] });
    seen.add("litespeed");
  }

  return found;
}
