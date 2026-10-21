/** The fix prompt: one universal prompt that works in any AI coding tool. */
import { Terminal, Info, Copy, Check } from "lucide-react";
import { cn } from "@/lib/utils";
import { useState, useCallback } from "react";

// ─── Fix Prompt card ──────────────────────────────────────────────────────────

/**
 * The prompt is the same for every tool. A report cannot know which assistant its reader will
 * paste it into, and the reader may use several, so it names no tool and uses none of a tool's
 * own commands. Nothing is wrapped around it per tool either: what you copy is what is shown.
 */
const WORKS_IN = "Claude Code, Cursor, Codex, GitHub Copilot, Windsurf, Grok Build, Gemini, ChatGPT, Lovable, Bolt, Replit, v0 and other AI coding tools";

export function AgentFixPromptCard({ prompt, fromTemplate = false, repoOnly = false }: { prompt: string; fromTemplate?: boolean; repoOnly?: boolean }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    void navigator.clipboard.writeText(prompt).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {});
  }, [prompt]);

  return (
    <div className="glass-card rounded-2xl p-6 border-t-4 border-t-violet-500">
      <p className="text-xs text-amber-300/90 mb-3">
        Review this prompt before you paste it into an AI tool. It is built from scanned data.
      </p>
      <div className="flex items-start justify-between gap-4 mb-4">
        <h3 className="text-lg font-bold flex items-center gap-2">
          <Terminal className="w-5 h-5 text-violet-400" />
          Fix with your AI coding tool
        </h3>
        <button
          onClick={handleCopy}
          className={cn(
            "shrink-0 flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all duration-200",
            copied
              ? "bg-green-500/20 text-green-400 border border-green-500/30"
              : "bg-violet-500/20 text-violet-300 border border-violet-500/30 hover:bg-violet-500/30",
          )}
        >
          {copied ? (
            <><Check className="w-4 h-4" /> Copied!</>
          ) : (
            <><Copy className="w-4 h-4" /> Copy prompt</>
          )}
        </button>
      </div>
      {fromTemplate && (
        <p className="text-xs text-muted-foreground mb-4">
          {repoOnly
            ? "Built from your findings, with the files each one is in. Every line is taken from the findings above."
            : "Built from your findings — the AI writer was unavailable for this scan. Every line is taken from the findings above."}
        </p>
      )}

      <div className="flex items-start gap-2 px-3 py-2 bg-violet-500/5 border border-violet-500/20 rounded-lg mb-3">
        <Info className="w-3.5 h-3.5 text-violet-400 mt-0.5 shrink-0" />
        <p className="text-xs text-violet-300/80">
          One prompt for every tool: it works in {WORKS_IN}. Paste it into your tool's agent or chat. A tool that can edit your files
          applies the fixes directly; a chat-only tool replies with the exact change to make for each one.
        </p>
      </div>

      <div className="bg-background border border-white/10 rounded-lg p-4 max-h-64 overflow-y-auto">
        <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap leading-relaxed">{prompt}</pre>
      </div>
    </div>
  );
}
