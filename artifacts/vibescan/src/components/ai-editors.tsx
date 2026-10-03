import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { customFetch } from "@workspace/api-client-react";
import { Check, Copy, KeyRound, Loader2, Trash2 } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Settings → AI editors and API: personal tokens, and the exact setup lines for the
 * MCP endpoint (Claude Code, Cursor) or the REST API (scripts and CI).
 *
 * A token has one scope. "mcp" opens the MCP endpoint only and "api" opens the REST API
 * only, so a token pasted into an editor config cannot also drive CI, or the reverse.
 *
 * A token is shown ONCE, at creation, already inlined into the setup commands
 * so there is nothing to assemble by hand — the server keeps only its hash.
 */

type Scope = "mcp" | "api";

interface TokenRow {
  id: string;
  name: string;
  prefix: string;
  scope: Scope;
  createdAt: string;
  lastUsedAt: string | null;
}

const listTokens = () => customFetch<{ tokens: TokenRow[]; max: number }>("/api/account/tokens");

function CopyBlock({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-semibold text-muted-foreground">{label}</span>
        <button
          type="button"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(value);
              setCopied(true);
              setTimeout(() => setCopied(false), 1800);
            } catch {
              /* clipboard blocked — the text is selectable */
            }
          }}
          className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
        >
          {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="text-xs bg-background/60 border border-white/10 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap break-all font-mono">
        {value}
      </pre>
    </div>
  );
}

function relative(iso: string | null): string {
  if (!iso) return "never used";
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 60) return mins <= 1 ? "used just now" : `used ${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `used ${hours} h ago`;
  return `used ${Math.round(hours / 24)} days ago`;
}

export function AiEditorsSection() {
  const queryClient = useQueryClient();
  const tokens = useQuery({ queryKey: ["api-tokens"], queryFn: listTokens });
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scope, setScope] = useState<Scope>("mcp");
  const [fresh, setFresh] = useState<{ name: string; token: string; scope: Scope } | null>(null);

  const endpoint = `${window.location.origin}/api/mcp`;
  const apiBase = `${window.location.origin}/api/v1`;

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setCreating(true);
    try {
      const row = await customFetch<TokenRow & { token: string }>("/api/account/tokens", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name.trim() || (scope === "api" ? "CI" : "AI editor"), scope }),
      });
      setFresh({ name: row.name, token: row.token, scope: row.scope ?? scope });
      setName("");
      await queryClient.invalidateQueries({ queryKey: ["api-tokens"] });
    } catch (err) {
      const msg = err instanceof Error ? err.message.replace(/^HTTP \d+ [^:]+: /, "") : "";
      setError(/revoke one/i.test(msg) ? msg : "Could not create a token. Please try again.");
    } finally {
      setCreating(false);
    }
  }

  async function revoke(id: string, name: string) {
    // One click used to revoke with no warning, and a revoked token cannot be
    // restored: every editor using it stops working at once. Same prompt as
    // stopping a monitor (pages/monitor.tsx).
    if (!confirm(`Revoke "${name}"? Any editor using this token stops working immediately. This cannot be undone.`)) return;
    await customFetch(`/api/account/tokens/${id}`, { method: "DELETE" }).catch(() => {});
    await queryClient.invalidateQueries({ queryKey: ["api-tokens"] });
  }

  return (
    <div className="space-y-6">
      <div role="radiogroup" aria-label="What the token is for" className="flex flex-wrap gap-2">
        {([["mcp", "AI editor (MCP)"], ["api", "Scripts and CI (REST API)"]] as const).map(([value, label]) => (
          <button
            key={value}
            type="button"
            role="radio"
            aria-checked={scope === value}
            onClick={() => setScope(value)}
            className={cn(
              "px-3.5 py-1.5 rounded-full text-sm border transition-colors",
              scope === value ? "bg-primary/15 border-primary/50 text-foreground" : "border-white/10 text-muted-foreground hover:text-foreground",
            )}
          >
            {label}
          </button>
        ))}
      </div>
      <form onSubmit={create} className="flex flex-col sm:flex-row gap-3">
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          maxLength={60}
          placeholder={scope === "api" ? "Name it — e.g. GitHub Actions" : "Name it — e.g. Claude Code on my laptop"}
          aria-label="Token name"
          className="flex-1 min-w-0 bg-background/60 border border-white/10 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-primary/50"
        />
        <button
          type="submit"
          disabled={creating}
          className="px-5 py-2.5 bg-primary text-primary-foreground font-semibold rounded-xl disabled:opacity-60 flex items-center justify-center gap-2"
        >
          {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : <KeyRound className="w-4 h-4" />}
          Create token
        </button>
      </form>
      {error && <p className="text-sm text-red-400">{error}</p>}

      {fresh && (
        <div className="rounded-xl border border-primary/30 bg-primary/5 p-4 space-y-4">
          <p className="text-sm">
            <span className="font-semibold">Copy this now — it won't be shown again.</span>{" "}
            <span className="text-muted-foreground">
              Anyone with it can run scans on your account. Revoke it below if it ever leaks.
            </span>
          </p>
          {fresh.scope === "api" ? (
            <>
              <CopyBlock
                label="Start a scan"
                value={`curl -X POST ${apiBase}/scans -H "Authorization: Bearer ${fresh.token}" -H "Content-Type: application/json" -d '{"url":"https://your-site.example"}'`}
              />
              <CopyBlock
                label="Wait for the result (up to 60 s) — replace SCAN_ID"
                value={`curl "${apiBase}/scans/SCAN_ID?wait=60" -H "Authorization: Bearer ${fresh.token}"`}
              />
              <CopyBlock label="The token alone" value={fresh.token} />
              <p className="text-xs text-muted-foreground">
                This token opens the REST API only, not the MCP endpoint or your account. Scans use your free scans,
                or your plan if you have one, and active tests run only on domains you've verified. The full description is
                at {apiBase}/openapi.json.
              </p>
            </>
          ) : (
            <>
          <CopyBlock
            label="Claude Code — run in a terminal"
            value={`claude mcp add --scope user --transport http secscan ${endpoint} --header "Authorization: Bearer ${fresh.token}"`}
          />
          <CopyBlock
            label="Cursor — add to ~/.cursor/mcp.json"
            value={JSON.stringify(
              { mcpServers: { secscan: { url: endpoint, headers: { Authorization: `Bearer ${fresh.token}` } } } },
              null,
              2,
            )}
          />
          <CopyBlock label="The token alone" value={fresh.token} />
          <p className="text-xs text-muted-foreground">
            Then restart your editor and ask it "How many SecScan scans do I have left?" to check it's connected
            (that uses no scan). After that, ask it to "scan my site with SecScan". Scans use your free scans, or
            your plan if you have one, exactly as on this site, and active tests run only on domains you've verified.
            Step-by-step help: secscan.info/ai-editors
          </p>
            </>
          )}
          <button type="button" onClick={() => setFresh(null)} className="text-xs text-muted-foreground hover:text-foreground underline">
            I've saved it
          </button>
        </div>
      )}

      <div className="space-y-2">
        {tokens.isLoading ? (
          <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
        ) : tokens.data?.tokens.length ? (
          tokens.data.tokens.map((t) => (
            <div key={t.id} className="flex flex-wrap items-center gap-3 rounded-xl border border-white/10 px-4 py-3">
              <KeyRound className="w-4 h-4 text-muted-foreground shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="font-medium truncate">{t.name}</div>
                <div className="text-xs text-muted-foreground font-mono">
                  {t.scope === "api" ? "API" : "MCP"} · {t.prefix}… · {relative(t.lastUsedAt)}
                </div>
              </div>
              <button
                type="button"
                onClick={() => revoke(t.id, t.name)}
                className={cn("inline-flex items-center gap-1.5 text-sm text-red-400 hover:text-red-300")}
              >
                <Trash2 className="w-4 h-4" /> Revoke
              </button>
            </div>
          ))
        ) : (
          <p className="text-sm text-muted-foreground">No tokens yet.</p>
        )}
      </div>
    </div>
  );
}
