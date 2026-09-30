/**
 * Small pure parsers for SPF and DMARC records, used by dnsChecks.ts.
 */

const LOOKUP_MECHANISMS = new Set(["include", "a", "mx", "ptr", "exists", "redirect"]);

/**
 * Number of terms in an SPF record that cost a DNS lookup under RFC 7208 §4.6.4:
 * include, a, mx, ptr, exists and the redirect modifier. Terms are parsed whole,
 * so the "a:" inside "ip6:2a00:1450::/32" or a hex group is never counted, and
 * ip4/ip6/all cost nothing. Nested includes are not expanded: the result is a
 * lower bound on the real count.
 */
export function countSpfLookups(record: string): number {
  let n = 0;
  for (const term of record.trim().split(/\s+/).slice(1)) {
    const name = term.replace(/^[+\-~?]/, "").split(/[:=/]/, 1)[0].toLowerCase();
    if (LOOKUP_MECHANISMS.has(name)) n++;
  }
  return n;
}

/**
 * Policy a receiver applies to the scanned host. A record inherited from a parent
 * domain governs subdomains through sp= when the record has one (RFC 7489 §6.3),
 * so "p=none; sp=reject" read from the parent does not leave a subdomain open.
 * Only the stricter direction is taken from sp=: this never invents a weaker
 * policy from sp=none.
 */
export function effectiveDmarcPolicy(record: string, inherited: boolean): string {
  const p = /(?:^|;)\s*p=(\w+)/i.exec(record)?.[1]?.toLowerCase() ?? "none";
  const sp = /(?:^|;)\s*sp=(\w+)/i.exec(record)?.[1]?.toLowerCase();
  if (inherited && p === "none" && (sp === "quarantine" || sp === "reject")) return sp;
  return p;
}
