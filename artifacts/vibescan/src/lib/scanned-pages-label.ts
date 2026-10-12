/**
 * The "Scanned N pages" chip on a report cover.
 *
 * When a bot-protection layer answered the scan, the pages it "scanned" were the
 * layer's challenge pages, not the site's, so a page count would suggest the
 * site was covered. The report's own notice explains what happened; the chip
 * stays out of its way.
 *
 * `pagesScanned` lists the pages crawled beyond the root, so the root adds one.
 */
export function scannedPagesLabel(
  pagesScanned: readonly string[] | null | undefined,
  intercepted: boolean | undefined,
): string | null {
  if (pagesScanned == null || intercepted === true) return null;
  const total = pagesScanned.length + 1;
  return `Scanned ${total} page${total !== 1 ? "s" : ""}`;
}
