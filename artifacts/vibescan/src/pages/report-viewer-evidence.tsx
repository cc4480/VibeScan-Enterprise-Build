/** The Download evidence pack button: a signed ZIP of the report, its SARIF, tables and a manifest, for an auditor or a customer. */
import { useState } from "react";
import { Loader2, PackageCheck } from "lucide-react";

/** The file name the server chose (Content-Disposition), or a sensible default. */
export function packFilename(disposition: string | null): string {
  const m = /filename="([^"\\/]+)"/.exec(disposition ?? "");
  return m?.[1] ?? "secscan-evidence.zip";
}

export function EvidencePackButton({ reportId }: { reportId: string }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function download() {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/reports/${encodeURIComponent(reportId)}/evidence-pack`, { credentials: "same-origin" });
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { error?: unknown } | null;
        throw new Error(typeof body?.error === "string" ? body.error : "The evidence pack could not be made. Please try again.");
      }
      const url = URL.createObjectURL(await res.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = packFilename(res.headers.get("content-disposition"));
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "The evidence pack could not be made.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={() => void download()}
        disabled={busy}
        title="A signed ZIP: the report, SARIF, findings and coverage tables, and a manifest of file hashes"
        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-secondary border border-white/10 text-sm font-medium hover:bg-white/10 transition-colors disabled:opacity-60"
      >
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <PackageCheck className="w-4 h-4" />}
        {busy ? "Preparing…" : "Evidence pack"}
      </button>
      {error && <span role="alert" className="text-sm text-red-400">{error}</span>}
    </>
  );
}
