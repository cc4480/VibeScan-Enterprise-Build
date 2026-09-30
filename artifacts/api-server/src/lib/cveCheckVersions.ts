/** Technology and version extraction from headers and HTML. */
import { isDistroPackaged } from "./bannerRules";
import { type DetectedVersion, VERSION_PATTERNS } from "./cve-patterns";

export function extractVersionedTechnologies(
  html: string,
  headers: Record<string, string>,
): DetectedVersion[] {
  const found: DetectedVersion[] = [];
  const seen = new Set<string>(); // avoid duplicates for same package

  const content = html.slice(0, 150_000); // only scan first 150KB

  for (const vp of VERSION_PATTERNS) {
    if (seen.has(vp.packageName)) continue;
    for (const rx of vp.patterns) {
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
