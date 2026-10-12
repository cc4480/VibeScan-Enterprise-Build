import type { SortBy } from "./report-viewer-types";
import { Vulnerability } from "@workspace/api-client-react";
import { getAuthHeaders } from "@/lib/auth-token";
import { useState, useMemo, useCallback, useEffect, useRef } from "react";
import { type DismissalEntry, computeVulnFp, vulnUniqueKey, VERIFICATION_THRESHOLD, SEVERITY_ORDER } from "./report-viewer-data";
import { splitScanNotes } from "@/lib/scan-notes";

/** Dismiss / undismiss state for one report: what the owner has marked as a false positive, with an undo toast. */
export function useReportDismissals(targetUrl: string | null | undefined, vulnerabilities: Vulnerability[]) {
  const [dismissedFps, setDismissedFps] = useState<Set<string>>(new Set());
  const [vulnFpMap, setVulnFpMap] = useState<Map<string, string>>(new Map());
  const [optimisticDismissKeys, setOptimisticDismissKeys] = useState<Set<string>>(new Set());
  const [undoToast, setUndoToast] = useState<{ key: string; vuln: Vulnerability } | null>(null);
  const undoToastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!targetUrl) return;
    fetch(`/api/dismissals?targetUrl=${encodeURIComponent(targetUrl)}`, { headers: getAuthHeaders() })
      .then((r) => (r.ok ? r.json() : []))
      .then((items: DismissalEntry[]) => {
        const fpSet = new Set<string>();
        for (const item of items) fpSet.add(item.fingerprint);
        setDismissedFps(fpSet);
      })
      .catch(() => {});
  }, [targetUrl]);

  const dismissFinding = useCallback(async (vuln: Vulnerability, targetUrl: string) => {
    const vKey = vulnUniqueKey(vuln);

    // Optimistic hide via per-vuln unique key (stays until server fingerprint arrives)
    setOptimisticDismissKeys((prev) => new Set([...prev, vKey]));

    // Show external undo toast (per-card button is gone once the card is hidden)
    if (undoToastTimerRef.current) clearTimeout(undoToastTimerRef.current);
    setUndoToast({ key: vKey, vuln });
    undoToastTimerRef.current = setTimeout(() => setUndoToast(null), 5000);

    try {
      const res = await fetch("/api/dismissals", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({
          targetUrl,
          findingName: vuln.name,
          findingCategory: vuln.category,
          findingEvidence: vuln.evidence ?? undefined,
          reason: "false_positive",
        }),
      });
      if (!res.ok) {
        setOptimisticDismissKeys((prev) => { const n = new Set(prev); n.delete(vKey); return n; });
        if (undoToastTimerRef.current) clearTimeout(undoToastTimerRef.current);
        setUndoToast(null);
        return;
      }
      const { fingerprint } = (await res.json()) as { fingerprint: string };
      // Promote from optimistic key to confirmed fingerprint
      setVulnFpMap((prev) => new Map([...prev, [vKey, fingerprint]]));
      setDismissedFps((prev) => new Set([...prev, fingerprint]));
      setOptimisticDismissKeys((prev) => { const n = new Set(prev); n.delete(vKey); return n; });
    } catch {
      setOptimisticDismissKeys((prev) => { const n = new Set(prev); n.delete(vKey); return n; });
      if (undoToastTimerRef.current) clearTimeout(undoToastTimerRef.current);
      setUndoToast(null);
    }
  }, []);

  const undismissFinding = useCallback(async (vuln: Vulnerability) => {
    const vKey = vulnUniqueKey(vuln);
    const fp = vulnFpMap.get(vKey);
    const tUrl = targetUrl;
    // Optimistically show the finding again
    setDismissedFps((prev) => { const n = new Set(prev); if (fp) n.delete(fp); return n; });
    setOptimisticDismissKeys((prev) => { const n = new Set(prev); n.delete(vKey); return n; });
    if (fp && tUrl) {
      try {
        const res = await fetch(
          `/api/dismissals/${fp}?targetUrl=${encodeURIComponent(tUrl)}`,
          { method: "DELETE", headers: getAuthHeaders() },
        );
        if (!res.ok) {
          setDismissedFps((prev) => new Set([...prev, fp]));
          return;
        }
        setVulnFpMap((prev) => { const n = new Map(prev); n.delete(vKey); return n; });
      } catch {
        setDismissedFps((prev) => new Set([...prev, fp]));
      }
    }
  }, [vulnFpMap, targetUrl]);

  // Pre-compute per-vuln fingerprints using the same SHA-256 algorithm as the server.
  // Runs as a fast async batch whenever the vulnerability list changes.
  useEffect(() => {
    if (!vulnerabilities.length) return;
    let cancelled = false;
    Promise.all(
      vulnerabilities.map((v) =>
        computeVulnFp(v.category, v.name, v.evidence).then(
          (fp) => [vulnUniqueKey(v), fp] as [string, string],
        ),
      ),
    ).then((pairs) => {
      if (!cancelled) setVulnFpMap((prev) => {
        const next = new Map(prev);
        for (const [k, fp] of pairs) next.set(k, fp);
        return next;
      });
    });
    return () => { cancelled = true; };
  }, [vulnerabilities]);

  return { dismissedFps, vulnFpMap, optimisticDismissKeys, undoToast, setUndoToast, undoToastTimerRef, dismissFinding, undismissFinding };
}

const sortVulns = (list: Vulnerability[], sortBy: SortBy): Vulnerability[] =>
  [...list].sort((a, b) => {
    if (sortBy === "severity") {
      const sd = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
      if (sd !== 0) return sd;
      return (b.cvssScore ?? 0) - (a.cvssScore ?? 0);
    }
    const cd = a.category.localeCompare(b.category);
    if (cd !== 0) return cd;
    return (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
  });

/**
 * Everything derived from the findings: sorted, filtered, split by confidence, grouped by category, counted.
 *
 * The scan's own notes (category "Scan Coverage") are not findings and are kept out of every list and
 * count here. They come back on their own as `scanNotes`, sorted and with dismissals applied, for the
 * "About this scan" section (see lib/scan-notes.ts). A category filter does not hide them: they describe
 * the scan, not a category of your site.
 */
export function useVulnGroups(input: {
  vulnerabilities: Vulnerability[];
  sortBy: SortBy;
  activeCategory: string | null;
  dismissedFps: Set<string>;
  vulnFpMap: Map<string, string>;
  optimisticDismissKeys: Set<string>;
  /** Ids of findings whose latest re-check says fixed. They leave the open lists and counts. */
  fixedIds?: ReadonlySet<string>;
}) {
  const { vulnerabilities, sortBy, activeCategory, dismissedFps, vulnFpMap, optimisticDismissKeys } = input;
  const fixedIds = input.fixedIds;
  const { findings, notes } = useMemo(() => splitScanNotes(vulnerabilities), [vulnerabilities]);
  const allSortedVulns = useMemo(() => sortVulns(findings, sortBy), [findings, sortBy]);
  // Verified fixed: shown in their own section, not in the open lists or counts below.
  const fixedVulns = useMemo(
    () => (fixedIds && fixedIds.size > 0 ? allSortedVulns.filter((v) => fixedIds.has(v.id)) : []),
    [allSortedVulns, fixedIds],
  );
  const sortedVulns = useMemo(
    () => (fixedVulns.length > 0 ? allSortedVulns.filter((v) => !fixedIds!.has(v.id)) : allSortedVulns),
    [allSortedVulns, fixedVulns, fixedIds],
  );

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const v of sortedVulns) {
      counts[v.category] = (counts[v.category] ?? 0) + 1;
    }
    return counts;
  }, [sortedVulns]);

  const sortedCategories = useMemo(
    () => Object.entries(categoryCounts).sort((a, b) => b[1] - a[1]).map(([c]) => c),
    [categoryCounts],
  );

  const isShown = useCallback((v: Vulnerability) => {
    const vKey = vulnUniqueKey(v);
    if (optimisticDismissKeys.has(vKey)) return false;
    const fp = vulnFpMap.get(vKey);
    return !fp || !dismissedFps.has(fp);
  }, [dismissedFps, vulnFpMap, optimisticDismissKeys]);

  const visibleVulns = useMemo(() => sortedVulns.filter(isShown), [sortedVulns, isShown]);
  const scanNotes = useMemo(() => sortVulns(notes, sortBy).filter(isShown), [notes, sortBy, isShown]);

  const dismissedCount = sortedVulns.length - visibleVulns.length + (notes.length - scanNotes.length);

  const filteredVulns = useMemo(
    () => activeCategory ? visibleVulns.filter((v) => v.category === activeCategory) : visibleVulns,
    [visibleVulns, activeCategory],
  );

  // Split into confirmed (confidence ≥ threshold) vs. needs verification
  const confirmedVulns = useMemo(
    () => filteredVulns.filter((v) => (v.confidence ?? 100) >= VERIFICATION_THRESHOLD),
    [filteredVulns],
  );
  const unverifiedVulns = useMemo(
    () => filteredVulns.filter((v) => (v.confidence ?? 100) < VERIFICATION_THRESHOLD),
    [filteredVulns],
  );

  // Grouped confirmed/unverified vulns by category (for grouped view)
  const groupedConfirmedVulns = useMemo(() => {
    const groups: Map<string, Vulnerability[]> = new Map();
    for (const v of confirmedVulns) {
      if (!groups.has(v.category)) groups.set(v.category, []);
      groups.get(v.category)!.push(v);
    }
    return groups;
  }, [confirmedVulns]);

  const groupedUnverifiedVulns = useMemo(() => {
    const groups: Map<string, Vulnerability[]> = new Map();
    for (const v of unverifiedVulns) {
      if (!groups.has(v.category)) groups.set(v.category, []);
      groups.get(v.category)!.push(v);
    }
    return groups;
  }, [unverifiedVulns]);

  // Unfiltered splits — used for PDF/copy so nothing is omitted when a category filter is active
  const allConfirmedVulns = useMemo(
    () => visibleVulns.filter((v) => (v.confidence ?? 100) >= VERIFICATION_THRESHOLD),
    [visibleVulns],
  );
  const allUnverifiedVulns = useMemo(
    () => visibleVulns.filter((v) => (v.confidence ?? 100) < VERIFICATION_THRESHOLD),
    [visibleVulns],
  );

  // Per-severity counts split by confidence — used for the header badges
  const confirmedSeverityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const v of allConfirmedVulns) counts[v.severity] = (counts[v.severity] ?? 0) + 1;
    return counts;
  }, [allConfirmedVulns]);

  const unverifiedSeverityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const v of allUnverifiedVulns) counts[v.severity] = (counts[v.severity] ?? 0) + 1;
    return counts;
  }, [allUnverifiedVulns]);

  return {
    findings, scanNotes, sortedVulns, fixedVulns, categoryCounts, sortedCategories, visibleVulns, dismissedCount, filteredVulns, confirmedVulns,
    unverifiedVulns, groupedConfirmedVulns, groupedUnverifiedVulns, allConfirmedVulns, allUnverifiedVulns,
    confirmedSeverityCounts, unverifiedSeverityCounts,
  };
}
