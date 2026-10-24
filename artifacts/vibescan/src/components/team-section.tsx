import { useState } from "react";
import { Link } from "wouter";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { customFetch } from "@workspace/api-client-react";
import { Copy, Loader2, LogOut, Trash2, UserPlus } from "lucide-react";
import { ROLE_CHOICES, inviteFormError, joinedOn, memberLabel, teamRefusal, type Role, type SharedTeam, type TeamMember } from "@/lib/team";

/**
 * Settings → Team: invite teammates as a viewer or an editor, see who has access and who has not accepted yet, change a role or
 * remove anyone at once; and the teams you have been invited onto. A viewer reads; an editor can also pause monitors and file
 * tickets from your reports. Neither can scan, spend your plan, change settings or see billing.
 */
export function TeamSection() {
  const queryClient = useQueryClient();
  const team = useQuery({ queryKey: ["team"], queryFn: () => customFetch<{ members: TeamMember[]; max: number }>("/api/team") });
  const shared = useQuery({ queryKey: ["team-shared"], queryFn: () => customFetch<{ teams: SharedTeam[] }>("/api/team/shared") });
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [link, setLink] = useState<{ email: string; url: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const refresh = () => Promise.all([queryClient.invalidateQueries({ queryKey: ["team"] }), queryClient.invalidateQueries({ queryKey: ["team-shared"] })]);

  async function invite(e: React.FormEvent) {
    e.preventDefault();
    const problem = inviteFormError(email);
    if (problem) { setError(problem); return; }
    setError(null);
    setLink(null);
    setBusy(true);
    try {
      const res = await customFetch<{ email: string; inviteUrl: string }>("/api/team/invites", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: email.trim(), role }),
      });
      setLink({ email: res.email, url: res.inviteUrl });
      setEmail("");
      await refresh();
    } catch (err) { setError(teamRefusal(err)); } finally { setBusy(false); }
  }

  async function changeRole(m: TeamMember, next: Role) {
    setError(null);
    try {
      await customFetch(`/api/team/members/${m.id}/role`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ role: next }) });
    } catch (err) { setError(teamRefusal(err)); }
    await refresh();
  }

  async function remove(m: TeamMember) {
    if (!confirm(m.status === "pending" ? `Withdraw the invitation to ${m.email}?` : `Remove ${m.email} from your team? They lose access to your reports straight away.`)) return;
    await customFetch(`/api/team/members/${m.id}`, { method: "DELETE" }).catch(() => {});
    await refresh();
  }

  async function leave(t: SharedTeam) {
    if (!confirm(`Leave ${t.ownerEmail ?? "this team"}? You will no longer be able to read their reports.`)) return;
    await customFetch(`/api/team/shared/${t.id}`, { method: "DELETE" }).catch(() => {});
    await refresh();
  }

  async function copy(url: string) {
    try { await navigator.clipboard.writeText(url); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch { /* the link is also shown to copy by hand */ }
  }

  if (team.isLoading) return <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />;
  const members = team.data?.members ?? [];

  return (
    <div className="space-y-6">
      <div className="space-y-3">
        <form onSubmit={invite} className="flex flex-col sm:flex-row gap-3 sm:items-end">
          <label className="block text-sm flex-1">
            <span className="block mb-1 text-muted-foreground">Invite a teammate by email</span>
            <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" placeholder="teammate@company.com" autoComplete="off" className="w-full rounded-lg bg-black/30 border border-white/10 px-3 py-2" />
          </label>
          <label className="block text-sm">
            <span className="block mb-1 text-muted-foreground">Role</span>
            <select value={role} onChange={(e) => setRole(e.target.value as Role)} aria-label="Role for the new teammate" className="rounded-lg bg-secondary border border-white/10 px-3 py-2">
              {ROLE_CHOICES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
            </select>
          </label>
          <button type="submit" disabled={busy} className="px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-semibold disabled:opacity-60 inline-flex items-center justify-center gap-2">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <UserPlus className="w-4 h-4" />} Send invitation
          </button>
        </form>
        {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
        {link && (
          <div className="rounded-xl border border-white/10 px-4 py-3 text-sm space-y-2">
            <div>Invitation sent to <strong>{link.email}</strong>. If it does not arrive, send them this link yourself. It only works for that address.</div>
            <div className="flex items-center gap-2">
              <code className="flex-1 min-w-0 truncate text-xs bg-black/30 rounded px-2 py-1">{link.url}</code>
              <button type="button" onClick={() => void copy(link.url)} className="inline-flex items-center gap-1.5 text-xs text-primary hover:underline shrink-0"><Copy className="w-3.5 h-3.5" /> {copied ? "Copied" : "Copy"}</button>
            </div>
          </div>
        )}
        <p className="text-xs text-muted-foreground">
          {ROLE_CHOICES.map((c) => `${c.label}: ${c.note}`).join(" ")} Neither can run scans, use your plan, change settings or see billing. Up to {team.data?.max ?? 10} people.
        </p>
        {members.map((m) => (
          <div key={m.id} className="flex flex-wrap items-center gap-3 rounded-xl border border-white/10 px-4 py-3">
            <div className="flex-1 min-w-0">
              <div className="font-medium truncate">{m.email}</div>
              <div className="text-xs text-muted-foreground">{m.status === "active" ? joinedOn(m.acceptedAt) || memberLabel(m) : memberLabel(m)}</div>
            </div>
            <select value={m.role} onChange={(e) => void changeRole(m, e.target.value as Role)} aria-label={`Role of ${m.email}`} className="rounded-lg bg-secondary border border-white/10 px-2 py-1 text-sm">
              {ROLE_CHOICES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
            </select>
            <button type="button" onClick={() => void remove(m)} aria-label={`Remove ${m.email}`} className="text-red-400 hover:text-red-300"><Trash2 className="w-4 h-4" /></button>
          </div>
        ))}
      </div>

      {(shared.data?.teams.length ?? 0) > 0 && (
        <div className="space-y-3 pt-6 border-t border-white/10">
          <h3 className="text-sm font-semibold">Shared with you</h3>
          {shared.data!.teams.map((t) => (
            <div key={t.id} className="flex flex-wrap items-center gap-3 rounded-xl border border-white/10 px-4 py-3">
              <div className="flex-1 min-w-0">
                <div className="font-medium truncate">{t.ownerEmail ?? "A SecScan account"}</div>
                <div className="text-xs text-muted-foreground">{[joinedOn(t.since), t.role === "editor" ? "Editor" : "Viewer"].filter(Boolean).join(" · ")}</div>
              </div>
              <Link href={`/team/shared/${t.id}`} className="text-sm text-primary hover:underline">View reports</Link>
              <button type="button" onClick={() => void leave(t)} className="inline-flex items-center gap-1.5 text-sm text-red-400 hover:text-red-300"><LogOut className="w-4 h-4" /> Leave</button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
