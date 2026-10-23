import { sql, type SQL, type AnyColumn } from "drizzle-orm";

/**
 * When two stored URLs are "the same site" for a lookup.
 *
 * A saved report's target is the URL the scan ENDED on (scanResult.finalUrl, after redirects), and a fetch always
 * reports a path: a scan of `seclayer.app` is stored as `https://seclayer.app/`. A monitor keeps the address as it
 * was typed, `https://seclayer.app`. Compared with `=`, those never meet, so a site that had been scanned looked
 * never-scanned: the new monitor's card read "Never", its history was empty, and the CVE watch (which skips a
 * subscription it can find no report for) quietly watched nothing.
 *
 * The key ignores what does not change which site it is: the scheme, a leading `www.`, a trailing slash, letter case and
 * a #fragment. It keeps the path and the query string, so `/app` and `/admin` on one host stay different. The SQL form
 * below does the same to a column; the two must stay in step (urlKey.test.ts runs the TypeScript form against the same cases).
 */
export function urlKey(url: string): string {
  return url
    .trim()
    .replace(/#.*$/, "")
    .replace(/^https?:\/\/(?:www[.])?/i, "")
    .replace(/\/+$/, "")
    .toLowerCase();
}

/** `column` holds the same site as `url`: the SQL form of urlKey. */
export function sameSite(column: AnyColumn, url: string): SQL {
  return sql`lower(regexp_replace(regexp_replace(regexp_replace(${column}, '#.*$', ''), '^https?://(www[.])?', '', 'i'), '/+$', '')) = ${urlKey(url)}`;
}
