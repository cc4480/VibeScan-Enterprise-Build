/**
 * The tests a running scan has finished, and a paced view of what to show.
 *
 * useLiveTests polls the API. useRevealed hands items out one at a time so they can
 * be read; `instant` shows everything at once (a scan that had already finished when
 * the page opened has nothing to watch).
 */
import { useEffect, useRef, useState } from "react";
import { customFetch } from "@workspace/api-client-react";
import type { LiveTest } from "./scan-terminal";

interface LiveResponse {
  status: string;
  totalChecks: number;
  /** owner/repo the scan reads, when a repository is connected to it. */
  repository?: string | null;
  tests: LiveTest[];
}

const POLL_MS = 1000;

/** Polls until the scan is over, then once more so the last tests are not missed. */
export function useLiveTests(scanId: string | undefined, status: string | undefined): { tests: LiveTest[]; totalChecks: number; repository: string | null } {
  const [state, setState] = useState<{ tests: LiveTest[]; totalChecks: number; repository: string | null }>({ tests: [], totalChecks: 0, repository: null });
  const over = status === "complete" || status === "failed";
  const finalFetched = useRef(false);

  useEffect(() => {
    if (!scanId) return undefined;
    let stopped = false;

    const load = async () => {
      try {
        const res = await customFetch<LiveResponse>(`/api/scans/${scanId}/live`);
        // Never shrink: a stale response must not un-show a test.
        if (!stopped) setState((prev) => (res.tests.length >= prev.tests.length ? { tests: res.tests, totalChecks: res.totalChecks, repository: res.repository ?? null } : prev));
      } catch {
        /* progress is a display; the status poll reports real failures */
      }
    };

    if (over) {
      if (!finalFetched.current) {
        finalFetched.current = true;
        void load();
      }
      return () => { stopped = true; };
    }

    void load();
    const timer = setInterval(load, POLL_MS);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [scanId, over]);

  return state;
}

/** The first N items, N growing at a pace set per item. `caughtUp` is true once all are shown. */
export function useRevealed<T>(
  items: T[],
  instant: boolean,
  delayOf: (item: T, waiting: number) => number,
): { shown: T[]; caughtUp: boolean } {
  const [count, setCount] = useState(0);
  const total = items.length;

  useEffect(() => {
    if (instant) {
      setCount(total);
      return undefined;
    }
    if (count >= total) return undefined;
    const timer = setTimeout(() => setCount((c) => Math.min(c + 1, total)), delayOf(items[count] as T, total - count));
    return () => clearTimeout(timer);
    // delayOf is a pure function of its arguments; it is not a dependency.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [count, total, instant]);

  const shown = instant ? items : items.slice(0, count);
  return { shown, caughtUp: shown.length >= total };
}
