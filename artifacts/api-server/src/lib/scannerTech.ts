import { extractVersionedTechnologies } from "./cveCheck";
import { detectTechnologies } from "./techFingerprint";

/**
 * Detected technologies, enriched with version numbers where available,
 * e.g. "jQuery" → "jQuery 1.11.3", "Nginx" → "Nginx 1.18.0".
 */
export function technologiesWithVersions(rawHeaders: Record<string, string>, html: string): string[] {
  const baseTechs = detectTechnologies(rawHeaders, html);
  const versionedTechs = extractVersionedTechnologies(html, rawHeaders);
  // Match by techName (canonical name from detectTechnologies) to avoid duplicates
  // e.g. "Apache HTTPD" techName="Apache" matches base tech "Apache" correctly
  const versionMap = new Map(versionedTechs.map((v) => [v.techName.toLowerCase(), v.version]));
  const technologies = baseTechs.map((tech) => {
    const ver = versionMap.get(tech.toLowerCase());
    return ver ? `${tech} ${ver}` : tech;
  });
  // Surface any additional versioned techs not already in the base list (by techName)
  const techNamesInBase = new Set(technologies.map((t) => t.split(" ")[0]?.toLowerCase()));
  for (const vt of versionedTechs) {
    if (!techNamesInBase.has(vt.techName.toLowerCase())) {
      technologies.push(`${vt.displayName} ${vt.version}`);
    }
  }
  return technologies;
}
