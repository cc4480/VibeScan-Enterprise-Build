/** The grade ring and finding card used by the printable report. */
import type { Vulnerability } from "@workspace/api-client-react";
import { ReproSteps } from "@/components/repro-steps";
import { SEVERITY_EMOJI } from "./report-viewer-data";

// ─── Print-friendly grade ring ────────────────────────────────────────────────

export function PrintGradeRing({ grade, score }: { grade: string; score: number }) {
  const colorMap: Record<string, string> = {
    A: "#059669", B: "#16a34a", C: "#ca8a04", D: "#ea580c", F: "#dc2626",
  };
  const graded = grade in colorMap;
  const color = graded ? colorMap[grade] : "#6b7280";
  const r = 52;
  const circumference = 2 * Math.PI * r;
  const dash = circumference * (graded ? score / 100 : 1);

  return (
    <div style={{ position: "relative", width: 120, height: 120, flexShrink: 0 }}>
      <svg width="120" height="120" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="60" cy="60" r={r} fill="none" stroke="#e5e7eb" strokeWidth="6" />
        <circle
          cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={`${dash} ${circumference - dash}`}
          strokeLinecap="round"
        />
      </svg>
      <div style={{
        position: "absolute", inset: 0, display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center",
      }}>
        <span style={{ fontSize: graded ? 36 : 44, fontWeight: 900, lineHeight: 1, color }}>{graded ? grade : "—"}</span>
        <span style={{ fontSize: 10, color: "#6b7280", marginTop: 2 }}>{graded ? `Risk: ${score}` : "Incomplete"}</span>
      </div>
    </div>
  );
}

// ─── Print-friendly vuln card (used inside PrintableReport) ───────────────────

export function PrintVulnCard({ vuln, index }: { vuln: Vulnerability; index: number }) {
  const borderColors: Record<string, string> = {
    critical: "border-red-300 bg-red-50",
    high:     "border-orange-300 bg-orange-50",
    medium:   "border-yellow-300 bg-yellow-50",
    low:      "border-blue-300 bg-blue-50",
    info:     "border-gray-300 bg-gray-50",
  };
  const headerColors: Record<string, string> = {
    critical: "text-red-800",
    high:     "text-orange-800",
    medium:   "text-yellow-800",
    low:      "text-blue-800",
    info:     "text-gray-700",
  };
  const emoji = SEVERITY_EMOJI[vuln.severity] ?? "•";
  const border = borderColors[vuln.severity] ?? "border-gray-300 bg-gray-50";
  const hdr = headerColors[vuln.severity] ?? "text-gray-700";

  return (
    <div className={`border rounded-lg overflow-hidden ${border}`} style={{ pageBreakInside: "avoid" }}>
      <div className={`px-4 py-2.5 flex items-center gap-3 border-b border-current/20 ${border}`}>
        <span className={`font-bold uppercase text-xs tracking-wider ${hdr}`}>{emoji} {vuln.severity}</span>
        <span className="font-semibold text-gray-900 text-sm">{index}. {vuln.name}</span>
        <span className="ml-auto text-xs text-gray-500 shrink-0">{vuln.category}</span>
      </div>
      <div className="px-4 py-3 bg-white space-y-3">
        <div>
          <p className="text-xs font-bold uppercase text-gray-400 mb-1 tracking-wider">Description</p>
          <p className="text-gray-800 text-sm leading-relaxed">{vuln.description}</p>
        </div>
        {vuln.evidence && (
          <div>
            <p className="text-xs font-bold uppercase text-gray-400 mb-1 tracking-wider">Evidence</p>
            <pre className="text-xs bg-gray-50 border border-gray-200 rounded p-2 whitespace-pre-wrap text-gray-600 font-mono">{vuln.evidence}</pre>
          </div>
        )}
        <ReproSteps evidence={vuln.evidence} />
        <div>
          <p className="text-xs font-bold uppercase text-gray-400 mb-1 tracking-wider">How to Fix</p>
          <div className="bg-green-50 border border-green-200 rounded p-3 text-sm text-gray-800 whitespace-pre-wrap">{vuln.solution}</div>
        </div>
        {(vuln.cweId || vuln.cvssScore != null || vuln.wstgId) && (
          <div className="flex gap-2 flex-wrap">
            {vuln.cweId && <span className="px-2 py-0.5 bg-gray-100 border border-gray-200 rounded text-xs text-gray-600">{vuln.cweId}</span>}
            {vuln.cvssScore != null && <span className="px-2 py-0.5 bg-gray-100 border border-gray-200 rounded text-xs text-gray-600">CVSS {vuln.cvssScore.toFixed(1)}</span>}
            {vuln.wstgId && <span className="px-2 py-0.5 bg-gray-100 border border-gray-200 rounded text-xs text-gray-600">{vuln.wstgId}</span>}
          </div>
        )}
      </div>
    </div>
  );
}
