/** Fix prompts for AI coding agents. */
import { Terminal, Info, Copy, Check } from "lucide-react";
import { cn } from "@/lib/utils";
import { useState, useMemo, useCallback } from "react";

// ─── Agent Fix Prompt card ────────────────────────────────────────────────────

export type AgentId = "cursor" | "claude_code" | "lovable" | "bolt" | "replit" | "generic";

export interface AgentConfig {
  id: AgentId;
  label: string;
  emoji: string;
  howTo: string;
  prefix?: string;
  suffix?: string;
}

export const AGENT_CONFIGS: AgentConfig[] = [
  {
    id: "cursor",
    label: "Cursor",
    emoji: "⚡",
    howTo: "Switch to Agent mode. Open a new chat, type @workspace to give it full codebase context, then paste the prompt below.",
    prefix: "You are working in @workspace (full codebase access). Fix ALL of the following security vulnerabilities. Check every relevant file — if the same insecure pattern appears in multiple places, fix all of them, not just the first.\n\n",
    suffix: "\n\nAfter applying all fixes, briefly confirm which files were changed.",
  },
  {
    id: "claude_code",
    label: "Claude Code",
    emoji: "🤖",
    howTo: "Paste the prompt into your Claude Code terminal session. It will read your codebase and apply edits directly.",
    suffix: "\n\nFor each fix, apply the change with /edit. Make the minimal secure change. After all fixes are applied, verify the app still builds.",
  },
  {
    id: "lovable",
    label: "Lovable",
    emoji: "💜",
    howTo: "Paste the prompt directly into the Lovable chat box. Lovable will apply each fix to your project files.",
  },
  {
    id: "bolt",
    label: "Bolt",
    emoji: "🔩",
    howTo: "Paste into the bolt.new chat window. Bolt will identify and edit the relevant files.",
  },
  {
    id: "replit",
    label: "Replit AI",
    emoji: "🔁",
    howTo: "Open the Replit AI panel (the AI button in the sidebar). Paste the prompt — it will apply fixes across your project.",
  },
  {
    id: "generic",
    label: "Other",
    emoji: "💬",
    howTo: "Copy and paste into any AI coding assistant — ChatGPT, Gemini, GitHub Copilot, Windsurf, etc.",
  },
];

export function AgentFixPromptCard({ prompt, fromTemplate = false }: { prompt: string; fromTemplate?: boolean }) {
  const [selectedAgent, setSelectedAgent] = useState<AgentId>("cursor");
  const [copied, setCopied] = useState(false);

  const agent = AGENT_CONFIGS.find((a) => a.id === selectedAgent) ?? AGENT_CONFIGS[0];

  const formattedPrompt = useMemo(() => {
    const prefix = agent?.prefix ?? "";
    const suffix = agent?.suffix ?? "";
    return `${prefix}${prompt}${suffix}`;
  }, [prompt, agent]);

  const handleCopy = useCallback(() => {
    void navigator.clipboard.writeText(formattedPrompt).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {});
  }, [formattedPrompt]);

  return (
    <div className="glass-card rounded-2xl p-6 border-t-4 border-t-violet-500">
      <div className="flex items-start justify-between gap-4 mb-4">
        <h3 className="text-lg font-bold flex items-center gap-2">
          <Terminal className="w-5 h-5 text-violet-400" />
          Fix with your AI agent
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
          Built from your findings — the AI writer was unavailable for this scan. Every line is taken from the findings above.
        </p>
      )}

      {/* Agent selector */}
      <div className="flex flex-wrap gap-2 mb-4">
        {AGENT_CONFIGS.map((a) => (
          <button
            key={a.id}
            onClick={() => setSelectedAgent(a.id)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all",
              selectedAgent === a.id
                ? "bg-violet-500/20 text-violet-300 border-violet-500/40"
                : "bg-white/5 text-muted-foreground border-white/10 hover:bg-white/10",
            )}
          >
            <span>{a.emoji}</span> {a.label}
          </button>
        ))}
      </div>

      {/* How-to instruction for selected agent */}
      <div className="flex items-start gap-2 px-3 py-2 bg-violet-500/5 border border-violet-500/20 rounded-lg mb-3">
        <Info className="w-3.5 h-3.5 text-violet-400 mt-0.5 shrink-0" />
        <p className="text-xs text-violet-300/80">{agent?.howTo}</p>
      </div>

      <div className="bg-background border border-white/10 rounded-lg p-4 max-h-64 overflow-y-auto">
        <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap leading-relaxed">{formattedPrompt}</pre>
      </div>
    </div>
  );
}
