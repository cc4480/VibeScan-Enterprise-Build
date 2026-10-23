/**
 * Cache-Control for the static frontend.
 *
 * Measured before this existed: every file went out as max-age=0, so
 * Cloudflare revalidated the 349 KB app bundle, the hero image and the logo
 * with Railway on every single request.
 *
 *   /assets/*       fingerprinted by Vite (index-DbbKlkkT.js) — a new build
 *                   gets a new name, so the old one can be cached forever.
 *   .html           re-checked every time, so a deploy is visible at once.
 *   /.well-known/*  short: verification and policy files must update quickly.
 *   everything else images, icons, robots.txt, llms.txt, sitemap — a day.
 */
const YEAR = 60 * 60 * 24 * 365;
const DAY = 60 * 60 * 24;

export function staticCacheControl(filePath: string): string {
  const p = filePath.replace(/\\/g, "/");
  if (p.endsWith(".html")) return "no-cache";
  if (p.includes("/assets/")) return `public, max-age=${YEAR}, immutable`;
  if (p.includes("/.well-known/")) return "public, max-age=300";
  return `public, max-age=${DAY}`;
}
