/**
 * The tests a running scan has finished, and a paced view of them.
 *
 * useLiveTests polls the API. useRevealed hands them out one at a time so they
 * can be read; `instant` shows everything at once (a scan that had already
 * finished when the page opened has nothing to watch).
 */
import { useEffect, useRef, useState } from "react";
import { customFetch } from "@workspace/api-client-react";
import { revealDelayMs, type LiveTest } from "./scan-terminal";

interface LiveResponse {
  status: string;
  tests: LiveTest[];
}

const POLL_MS = 1000;

/** Polls until the scan is over, then once more so the last tests are not missed. */
export function useLiveTests(scanId: string | undefined, status: string | undefined): LiveTest[] {
  const [tests, setTests] = useState<LiveTest[]>([]);
  const over = status === "complete" || status === "failed";
  const finalFetched = useRef(false);

  useEffect(() => {
    if (!scanId) return undefined;
    let stopped = false;

    const load = async () => {
      try {
        const res = await customFetch<LiveResponse>(`/api/scans/${scanId}/live`);
        // Never shrink: a stale response must not un-show a test.
        if (!stopped) setTests((prev) => (res.tests.length >= prev.length ? res.tests : prev));
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

  return tests;
}

/** The first N tests, N growing at a readable pace. `caughtUp` is true once all are shown. */
export function useRevealed(tests: LiveTest[], instant: boolean): { shown: LiveTest[]; caughtUp: boolean } {
  const [count, setCount] = useState(0);
  const total = tests.length;

  useEffect(() => {
    if (instant) {
      setCount(total);
      return undefined;
    }
    if (count >= total) return undefined;
    const timer = setTimeout(() => setCount((c) => Math.min(c + 1, total)), revealDelayMs(total - count));
    return () => clearTimeout(timer);
  }, [count, total, instant]);

  const shown = instant ? tests : tests.slice(0, count);
  return { shown, caughtUp: shown.length >= total };
}
