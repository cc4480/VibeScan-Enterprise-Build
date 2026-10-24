/** The Download PDF button. */
import { Loader2, Download } from "lucide-react";
import { useState, useRef } from "react";
import { APP_ORIGIN } from "@/lib/origin";
import { PdfReport } from "@/components/pdf-report";
import { exportElementToPdf } from "@/lib/pdfExport";
import { pdfFilename, pdfFooter, type Brand } from "@/lib/branding";
import { type PrintableReportData } from "./report-viewer-print";

export function DownloadPDFButton({ data, brand = null }: { data: PrintableReportData; brand?: Brand | null }) {
  const [generating, setGenerating] = useState(false);
  const [showOffscreen, setShowOffscreen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const handleDownload = async () => {
    if (generating) return;
    setGenerating(true);
    setShowOffscreen(true);
    // Wait for React to render the off-screen PrintableReport
    await new Promise<void>((r) => setTimeout(r, 300));

    try {
      const container = containerRef.current;
      if (!container) return;

      let host: string | null = null;
      try {
        host = new URL(data.targetUrl).hostname.replace(/^www\./, "");
      } catch {
        // keep the default name
      }
      const filename = pdfFilename(brand, host);
      const when = new Date(data.scannedAt).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
      await exportElementToPdf(container, { filename, footer: pdfFooter(brand, APP_ORIGIN, when) });
    } finally {
      setShowOffscreen(false);
      setGenerating(false);
    }
  };

  return (
    <>
      {/* Off-screen container for PDF capture — visible to html2canvas but off-viewport */}
      {showOffscreen && (
        <div
          ref={containerRef}
          style={{
            position: "fixed",
            left: "-9999px",
            top: 0,
            width: "794px",
            backgroundColor: "#09090b",
            zIndex: -1,
            pointerEvents: "none",
          }}
        >
          {/* The app's own dark look, not the white print layout (that stays for Ctrl+P). */}
          <PdfReport {...data} brand={brand} />
        </div>
      )}

      <button
        onClick={() => void handleDownload()}
        disabled={generating}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-secondary border border-white/10 text-sm font-medium hover:bg-white/10 transition-colors disabled:opacity-60"
      >
        {generating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
        {generating ? "Generating…" : "Download PDF"}
      </button>
    </>
  );
}
