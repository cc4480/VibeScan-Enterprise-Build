import { reproSteps } from "@/lib/repro-steps";

/**
 * Under a finding's evidence: the command that repeats the scanner's request, and what
 * to look for in the reply. Renders nothing unless the evidence is a request we can
 * replay exactly (see lib/repro-steps.ts).
 */
export function ReproSteps({ evidence, dark = false }: { evidence?: string | null; dark?: boolean }) {
  const steps = reproSteps(evidence);
  if (!steps) return null;
  return (
    <div>
      <p className={dark ? "text-xs font-bold text-muted-foreground uppercase tracking-wider mb-1.5" : "text-xs font-bold uppercase text-gray-400 mb-1 tracking-wider"}>See it yourself</p>
      <pre className={dark ? "bg-background border border-white/10 rounded-lg p-3 text-xs font-mono text-muted-foreground whitespace-pre-wrap break-all" : "text-xs bg-gray-50 border border-gray-200 rounded p-2 whitespace-pre-wrap break-all text-gray-700 font-mono"}>{steps.command}</pre>
      {steps.expect.length > 0 && (
        <p className="text-xs text-gray-500 mt-1">
          Look for: {steps.expect.map((e, i) => (<span key={i}>{i > 0 && "; "}<code className="font-mono">{e}</code></span>))}
        </p>
      )}
    </div>
  );
}
