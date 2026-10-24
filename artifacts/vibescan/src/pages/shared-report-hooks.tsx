import { useState, useEffect, useRef } from "react";
import { Download } from "lucide-react";
import { APP_ORIGIN } from "@/lib/origin";
import { exportElementToPdf } from "@/lib/pdfExport";
import { type SharedReportData } from "./shared-report-components";
import { brandOf, pdfFilename, pdfFooter } from "@/lib/branding";

/** Loads a shared report by its token. */
export function useSharedReportData(token: string) {
  const [report, setReport] = useState<SharedReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<{ status: number; message: string } | null>(null);

  useEffect(() => {
    if (!token) return;
    fetch(`/api/share/${token}`)
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({ error: "Unknown error" }));
          setError({ status: r.status, message: body.error ?? "Failed to load report" });
          return;
        }
        const data = await r.json();
        setReport(data as SharedReportData);
      })
      .catch(() => setError({ status: 500, message: "Network error" }))
      .finally(() => setLoading(false));
  }, [token]);

  return { report, loading, error };
}

/** Download-as-PDF state for a shared report: renders the printable copy off-screen, then exports it. */
export function useSharedReportPdf(report: SharedReportData | null) {
  // PDF generation state — must be declared before any conditional returns (Rules of Hooks)
  const pdfContainerRef = useRef<HTMLDivElement>(null);
  const [generatingPdf, setGeneratingPdf] = useState(false);
  const [showPdfContainer, setShowPdfContainer] = useState(false);

  const handleDownloadPDF = async () => {
    if (!report) return;
    const dateStr = new Date(report.scannedAt).toLocaleDateString("en-US", {
      year: "numeric", month: "long", day: "numeric",
    });
    if (generatingPdf) return;
    setGeneratingPdf(true);
    setShowPdfContainer(true);
    await new Promise<void>((r) => setTimeout(r, 300));
    try {
      const container = pdfContainerRef.current;
      if (!container) return;

      let host: string | null = null;
      try {
        host = new URL(report.targetUrl).hostname.replace(/^www\./, "");
      } catch {
        // keep the default name
      }
      const filename = pdfFilename(brandOf(report), host);
      await exportElementToPdf(container, { filename, footer: pdfFooter(brandOf(report), APP_ORIGIN, dateStr) });
    } finally {
      setShowPdfContainer(false);
      setGeneratingPdf(false);
    }
  };

  return { pdfContainerRef, generatingPdf, showPdfContainer, handleDownloadPDF };
}
