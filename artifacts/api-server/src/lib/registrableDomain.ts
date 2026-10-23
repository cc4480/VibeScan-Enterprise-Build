/**
 * Registrable ("organisational") domain of a hostname, for checks that must ask
 * about one specific name (DKIM selectors) rather than walk up a chain.
 *
 * There is no public-suffix-list dependency in this repo (no tldts/psl), so
 * this carries a small list of common multi-label public suffixes. Limit: a
 * suffix not listed here (an uncommon ccTLD second level, or a private suffix
 * such as a hosting platform's) is treated as a plain single-label TLD, so the
 * result can be one label too short there, never a bare public suffix for the
 * listed ones. Callers that only want to avoid asking about a bare suffix
 * such as "co.uk" are served correctly.
 */
const MULTI_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk", "nhs.uk", "police.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au",
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ed.jp",
  "com.br", "net.br", "org.br", "gov.br", "edu.br",
  "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in", "gen.in", "ind.in",
  "co.za", "org.za", "net.za", "gov.za", "ac.za",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
  "com.hk", "org.hk", "edu.hk", "gov.hk",
  "com.sg", "org.sg", "edu.sg", "gov.sg",
  "com.mx", "org.mx", "gob.mx", "edu.mx",
  "com.ar", "com.co", "com.pe", "com.ve", "com.uy", "com.ec",
  "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr",
  "com.tw", "org.tw", "edu.tw", "gov.tw",
  "com.tr", "org.tr", "gov.tr", "edu.tr",
  "com.ua", "com.pl", "com.pt", "com.es", "com.ru", "com.my", "com.ph", "com.vn", "com.sa", "com.eg", "com.ng",
  "co.il", "org.il", "ac.il", "gov.il",
  "co.id", "or.id", "go.id", "ac.id",
  "co.th", "ac.th", "go.th", "or.th",
  "co.ke", "or.ke", "go.ke", "ac.ke",
]);

export function registrableDomain(hostname: string): string {
  const labels = hostname.toLowerCase().split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  return labels.slice(MULTI_LABEL_SUFFIXES.has(lastTwo) ? -3 : -2).join(".");
}
