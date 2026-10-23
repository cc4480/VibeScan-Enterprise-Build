import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { customFetch } from "@workspace/api-client-react";
import { ExternalLink, Loader2, Trash2 } from "lucide-react";
import { APP_ORIGIN } from "@/lib/origin";
import { accentOrNull } from "@/lib/trust-page";

/**
 * Settings → Trust pages: a public page for a domain you have verified, showing the latest grade and scan date under your
 * name and colour. It never lists what the findings are, and it goes dark by itself when the domain stops being verified.
 */
interface Page { domain: string; enabled: boolean; displayName: string | null; accent: string | null }
interface Mine { pages: Page[]; available: string[] }

const refusal = (err: unknown): string => {
  const data = (err as { data?: { error?: unknown } } | null)?.data;
  return typeof data?.error === "string" ? data.error : "That did not work. Please try again.";
};

function PageRow({ page, onChanged }: { page: Page; onChanged: () => Promise<unknown> }) {
  const [name, setName] = useState(page.displayName ?? "");
  const [accent, setAccent] = useState(page.accent ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const url = `${APP_ORIGIN}/trust/${page.domain}`;

  async function save(patch: { enabled?: boolean } = {}) {
    setBusy(true);
    setError(null);
    try {
      await customFetch(`/api/trust-pages/${encodeURIComponent(page.domain)}`, {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ displayName: name, accent: accent.trim(), enabled: patch.enabled ?? page.enabled }),
      });
      await onChanged();
    } catch (err) { setError(refusal(err)); } finally { setBusy(false); }
  }
  async function remove() {
    if (!confirm(`Delete the trust page for ${page.domain}? The link stops working.`)) return;
    setBusy(true);
    await customFetch(`/api/trust-pages/${encodeURIComponent(page.domain)}`, { method: "DELETE" }).catch(() => {});
    await onChanged();
    setBusy(false);
  }
  const swatch = accentOrNull(accent.trim().toLowerCase());

  return (
    <div className="rounded-xl border border-white/10 px-4 py-4 space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex-1 min-w-0">
          <div className="font-medium truncate">{page.domain}</div>
          <a href={url} target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-1 break-all">
            {url} <ExternalLink className="w-3 h-3 shrink-0" />
          </a>
        </div>
        <label className="inline-flex items-center gap-2 text-sm">
          <input type="checkbox" checked={page.enabled} disabled={busy} onChange={(e) => void save({ enabled: e.target.checked })} /> Public
        </label>
        <button type="button" onClick={() => void remove()} disabled={busy} aria-label={`Delete the trust page for ${page.domain}`} className="text-red-400 hover:text-red-300 disabled:opacity-60">
          <Trash2 className="w-4 h-4" />
        </button>
      </div>
      <div className="grid sm:grid-cols-[1fr_9rem_auto] gap-3 items-end">
        <label className="block text-sm">
          <span className="block mb-1 text-muted-foreground">Name shown</span>
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={80} placeholder="Acme Ltd" className="w-full rounded-lg bg-black/30 border border-white/10 px-3 py-2" />
        </label>
        <label className="block text-sm">
          <span className="block mb-1 text-muted-foreground">Colour</span>
          <span className="flex items-center gap-2">
            <input value={accent} onChange={(e) => setAccent(e.target.value)} maxLength={7} placeholder="#1a73e8" spellCheck={false} className="w-full rounded-lg bg-black/30 border border-white/10 px-3 py-2" />
            <span className="w-5 h-5 rounded shrink-0 border border-white/20" style={swatch ? { backgroundColor: swatch } : undefined} aria-hidden />
          </span>
        </label>
        <button type="button" onClick={() => void save()} disabled={busy} className="px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-semibold disabled:opacity-60 inline-flex items-center gap-2">
          {busy && <Loader2 className="w-4 h-4 animate-spin" />} Save
        </button>
      </div>
      {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
    </div>
  );
}

export function TrustPagesSection() {
  const queryClient = useQueryClient();
  const mine = useQuery({ queryKey: ["trust-pages"], queryFn: () => customFetch<Mine>("/api/trust-pages") });
  const [creating, setCreating] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["trust-pages"] });

  async function create(domain: string) {
    setCreating(domain);
    setError(null);
    try {
      await customFetch(`/api/trust-pages/${encodeURIComponent(domain)}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}) });
      await refresh();
    } catch (err) { setError(refusal(err)); } finally { setCreating(null); }
  }

  if (mine.isLoading) return <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />;
  const data = mine.data;
  return (
    <div className="space-y-3">
      {data?.pages.map((p) => <PageRow key={p.domain} page={p} onChanged={refresh} />)}
      {data && data.available.length > 0 && (
        <div className="space-y-2">
          <p className="text-sm text-muted-foreground">Create a page for a verified domain:</p>
          <div className="flex flex-wrap gap-2">
            {data.available.map((d) => (
              <button key={d} type="button" onClick={() => void create(d)} disabled={creating !== null} className="px-3 py-1.5 rounded-lg border border-white/15 text-sm font-medium disabled:opacity-60 inline-flex items-center gap-2">
                {creating === d && <Loader2 className="w-3.5 h-3.5 animate-spin" />} {d}
              </button>
            ))}
          </div>
        </div>
      )}
      {data && data.pages.length === 0 && data.available.length === 0 && (
        <p className="text-sm text-muted-foreground">Verify a domain first (Domains), then you can publish a trust page for it. A trust page can only speak for a domain you have proved you control.</p>
      )}
      {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
    </div>
  );
}
