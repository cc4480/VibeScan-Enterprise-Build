/** Pages scanned and the detected software inventory. */
import { Globe, Package, AlertTriangle, ChevronDown, Search, Minus } from "lucide-react";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";
import { useState, useMemo, useCallback } from "react";
import type { Vulnerability } from "@workspace/api-client-react";
import { parseTechVersion } from "./report-viewer-data";
import { safeHref } from "@/lib/safe-href";

// ─── Pages Scanned card ───────────────────────────────────────────────────────

export function PagesScannedCard({
  rootUrl,
  pagesScanned,
  probedNotFound,
}: {
  rootUrl: string;
  pagesScanned: string[];
  probedNotFound?: string[];
}) {
  const [open, setOpen] = useState(false);

  const allPages = useMemo(() => {
    const pages: { label: string; url: string; isRoot: boolean }[] = [
      { label: rootUrl, url: rootUrl, isRoot: true },
    ];
    for (const url of pagesScanned) {
      try {
        const path = new URL(url).pathname;
        pages.push({ label: path, url, isRoot: false });
      } catch {
        pages.push({ label: url, url, isRoot: false });
      }
    }
    return pages;
  }, [rootUrl, pagesScanned]);

  const notFoundPages = useMemo(() => {
    return (probedNotFound ?? []).map((url) => {
      try { return { label: new URL(url).pathname, url }; }
      catch { return { label: url, url }; }
    });
  }, [probedNotFound]);

  return (
    <div className="glass-card rounded-2xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-5 hover:bg-white/[0.02] transition-colors"
      >
        <h3 className="text-sm font-bold flex items-center gap-2">
          <Search className="w-4 h-4 text-sky-400" />
          Pages Scanned
          <span className="px-1.5 py-0.5 bg-secondary text-xs rounded-full text-muted-foreground">{allPages.length}</span>
          {notFoundPages.length > 0 && (
            <span className="px-1.5 py-0.5 bg-secondary text-xs rounded-full text-muted-foreground/60">
              {notFoundPages.length} not found
            </span>
          )}
        </h3>
        <ChevronDown className={cn("w-4 h-4 text-muted-foreground transition-transform", open && "rotate-180")} />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 border-t border-white/5 pt-3 space-y-1">
              <p className="text-xs text-muted-foreground mb-3">All URLs visited during this scan, including the root page and crawled inner pages.</p>
              {allPages.map((page, i) => (
                <div key={i} className="flex items-center gap-2 py-1">
                  <Globe className={cn("w-3 h-3 shrink-0", page.isRoot ? "text-sky-400" : "text-muted-foreground/50")} />
                  {safeHref(page.url) ? (
                    <a
                      href={safeHref(page.url)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs font-mono text-muted-foreground hover:text-foreground transition-colors truncate"
                      title={page.url}
                    >
                      {page.label}
                    </a>
                  ) : (
                    <span className="text-xs font-mono text-muted-foreground truncate" title={page.url}>
                      {page.label}
                    </span>
                  )}
                  {page.isRoot && (
                    <span className="shrink-0 text-[9px] px-1 py-0.5 bg-sky-500/10 text-sky-400/70 border border-sky-500/20 rounded font-medium leading-none">
                      root
                    </span>
                  )}
                </div>
              ))}

              {notFoundPages.length > 0 && (
                <div className="mt-4 pt-3 border-t border-white/5">
                  <p className="text-xs text-muted-foreground/60 mb-2 font-medium">Probed (not found)</p>
                  {notFoundPages.map((page, i) => (
                    <div key={i} className="flex items-center gap-2 py-1">
                      <Minus className="w-3 h-3 shrink-0 text-muted-foreground/30" />
                      <span
                        className="text-xs font-mono text-muted-foreground/40 truncate"
                        title={page.url}
                      >
                        {page.label}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─── Software Inventory card ──────────────────────────────────────────────────

export function SoftwareInventoryCard({
  technologies,
  vulnerabilities,
}: {
  technologies: string[];
  vulnerabilities: Vulnerability[];
}) {
  const versionedTechs = useMemo(() => {
    const seen = new Set<string>();
    return technologies
      .map(parseTechVersion)
      .filter((t) => {
        if (t.version === null) return false;
        const key = `${t.name.toLowerCase()}@${t.version.toLowerCase()}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
  }, [technologies]);

  // Count CVEs per tech by matching vuln names like "jQuery 1.11.3 — Known Vulnerability ..."
  // or evidence lines like "Detected: jQuery 1.11.3" as a fallback
  const cveCountFor = useCallback(
    (name: string, version: string) => {
      const namePrefix = `${name.toLowerCase()} ${version.toLowerCase()} \u2014`; // em dash separator
      const evidenceTag = `detected: ${name.toLowerCase()} ${version.toLowerCase()}`;
      return vulnerabilities.filter((v) =>
        v.name.toLowerCase().startsWith(namePrefix) ||
        (v.evidence?.toLowerCase().includes(evidenceTag) ?? false)
      ).length;
    },
    [vulnerabilities],
  );

  const cveTotal = useMemo(
    () => versionedTechs.reduce((sum, t) => sum + cveCountFor(t.name, t.version!), 0),
    [versionedTechs, cveCountFor],
  );

  const [open, setOpen] = useState(() => cveTotal > 0);

  if (versionedTechs.length === 0) return null;

  return (
    <div className="glass-card rounded-2xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-5 hover:bg-white/[0.02] transition-colors"
      >
        <h3 className="text-sm font-bold flex items-center gap-2">
          <Package className="w-4 h-4 text-yellow-400" />
          Software Inventory
          <span className="px-1.5 py-0.5 bg-secondary text-xs rounded-full text-muted-foreground">{versionedTechs.length}</span>
          {cveTotal > 0 && (
            <span className="flex items-center gap-1 text-[11px] font-semibold text-red-400 bg-red-950/60 px-2 py-0.5 rounded-full border border-red-500/25 leading-none">
              <AlertTriangle className="w-3 h-3" />
              {cveTotal} CVE{cveTotal !== 1 ? "s" : ""}
            </span>
          )}
        </h3>
        <ChevronDown className={cn("w-4 h-4 text-muted-foreground transition-transform", open && "rotate-180")} />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 space-y-2 border-t border-white/5 pt-3">
              <p className="text-xs text-muted-foreground mb-3">Versioned components found during the scan that were checked for known CVEs.</p>
              {versionedTechs.map((t, i) => {
                const cveCount = cveCountFor(t.name, t.version!);
                return (
                  <div key={i} className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-foreground/90">{t.name}</span>
                      <span className="px-1.5 py-0.5 bg-yellow-500/15 text-yellow-400 text-[10px] font-mono rounded border border-yellow-500/20 leading-none">
                        {t.version}
                      </span>
                    </div>
                    {cveCount > 0 ? (
                      <span className="flex items-center gap-1 text-xs font-semibold text-red-400 bg-red-950/50 px-2 py-0.5 rounded-full border border-red-500/20">
                        <AlertTriangle className="w-3 h-3" /> {cveCount} CVE{cveCount !== 1 ? "s" : ""}
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">No CVEs found</span>
                    )}
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
