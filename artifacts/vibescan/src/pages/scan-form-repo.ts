/**
 * The address a repository-only scan is sent with: the repository's own https://github.com/owner/repo URL, which the
 * server reads as "scan this repository and no website". Null while what was typed is not a repository.
 */
export function repoScanAddress(value: string): string | null {
  const v = value.trim();
  if (v === "") return null;
  if (/^https?:\/\/(www\.)?github\.com\/[\w.-]+\/[\w.-]+/i.test(v)) return v.replace(/^http:/i, "https:");
  return /^[\w.-]+\/[\w.-]+$/.test(v) ? `https://github.com/${v}` : null;
}
