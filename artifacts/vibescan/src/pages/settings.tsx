import { useState } from "react";
import { useSeo } from "@/lib/seo";
import { useToast } from "@/hooks/use-toast";
import { Trash2, Loader2, AlertTriangle } from "lucide-react";
import { deleteAccount } from "@/lib/account-api";

function getFriendlyError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err ?? "");
  if (!msg) return "Something went wrong. Please try again.";
  if (/unauthorized|401/i.test(msg)) return "Session expired. Please sign in again.";
  const clean = msg.replace(/^HTTP \d{3} [^:]+:\s*/, "");
  return clean.length > 160 ? clean.slice(0, 160) + "…" : clean;
}

export default function SettingsPage() {
  useSeo({ title: "Settings — SecScan", noindex: true });
  const { toast } = useToast();

  // Typing the word is the confirmation. A dialog with a red button is too easy
  // to dismiss by reflex for something with no undo.
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [deleting, setDeleting] = useState(false);

  const handleDeleteAccount = async () => {
    setDeleting(true);
    try {
      await deleteAccount();
      // Full reload rather than a router push: every cached query belongs to an
      // account that no longer exists.
      window.location.href = "/";
    } catch (err) {
      setDeleting(false);
      toast({
        title: "Couldn't delete account",
        description: getFriendlyError(err),
        variant: "destructive",
      });
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="mb-10">
        <h1 className="text-3xl md:text-4xl font-bold tracking-tight mb-3">Settings</h1>
        <p className="text-muted-foreground text-lg">Manage your account.</p>
      </div>

      <div className="glass-panel p-6 sm:p-10 rounded-3xl border border-red-500/20">
        <div className="flex items-start gap-4 mb-6">
          <div className="w-12 h-12 rounded-2xl bg-red-500/10 flex items-center justify-center border border-red-500/20 shrink-0">
            <AlertTriangle className="w-6 h-6 text-red-400" />
          </div>
          <div>
            <h2 className="text-xl font-bold mb-1">Delete account</h2>
            <p className="text-sm text-muted-foreground leading-relaxed">
              Permanently erases your account, every scan and report, your saved credentials,
              your credits and your verified domains. Share links stop working. This cannot be
              undone and there is no grace period. Payment records are kept by Stripe where
              accounting law requires it.
            </p>
          </div>
        </div>

        <label className="block text-sm text-muted-foreground mb-2">
          Type <span className="font-mono text-foreground">DELETE</span> to confirm
        </label>
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={deleteConfirm}
            onChange={(e) => setDeleteConfirm(e.target.value)}
            aria-label="Type DELETE to confirm"
            className="flex-1 px-4 py-3 rounded-xl bg-black/30 border border-white/10 text-sm font-mono focus:outline-none focus:border-red-500/50"
          />
          <button
            type="button"
            onClick={handleDeleteAccount}
            disabled={deleteConfirm !== "DELETE" || deleting}
            className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-red-500/90 text-white font-bold text-sm disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {deleting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
            Delete my account
          </button>
        </div>
      </div>
    </div>
  );
}
