import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useSeo } from "@/lib/seo";
import { useToast } from "@/hooks/use-toast";
import {
  useGetDeepseekKeyStatus,
  useSetDeepseekKey,
  useDeleteDeepseekKey,
  getGetDeepseekKeyStatusQueryKey,
} from "@workspace/api-client-react";
import { KeyRound, Eye, EyeOff, Trash2, Loader2, ShieldCheck, ExternalLink, AlertTriangle } from "lucide-react";
import { deleteAccount } from "@/lib/account-api";

function getFriendlyError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err ?? "");
  if (!msg) return "Something went wrong. Please try again.";
  if (/unauthorized|401/i.test(msg)) return "Session token missing. Please refresh the page and try again.";
  const clean = msg.replace(/^HTTP \d{3} [^:]+:\s*/, "");
  return clean.length > 160 ? clean.slice(0, 160) + "…" : clean;
}

export default function SettingsPage() {
  useSeo({ title: "Settings — SecScan", noindex: true });
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [showKey, setShowKey] = useState(false);
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

  const { data: keyStatus, isLoading } = useGetDeepseekKeyStatus();
  const setKey = useSetDeepseekKey();
  const deleteKey = useDeleteDeepseekKey();

  const invalidateStatus = () =>
    queryClient.invalidateQueries({ queryKey: getGetDeepseekKeyStatusQueryKey() });

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    const apiKey = apiKeyInput.trim();
    if (!apiKey) return;

    setKey.mutate(
      { data: { apiKey } },
      {
        onSuccess: () => {
          setApiKeyInput("");
          invalidateStatus();
          toast({
            title: "DeepSeek key saved",
            description: "Deep scans will now use your personal API key for AI fix prompts.",
          });
        },
        onError: (err) => {
          toast({
            title: "Couldn't save key",
            description: getFriendlyError(err),
            variant: "destructive",
          });
        },
      },
    );
  };

  const handleRemove = () => {
    deleteKey.mutate(undefined, {
      onSuccess: () => {
        invalidateStatus();
        toast({
          title: "DeepSeek key removed",
          description: "Deep scans will fall back to the shared default key, if configured.",
        });
      },
      onError: (err) => {
        toast({
          title: "Couldn't remove key",
          description: getFriendlyError(err),
          variant: "destructive",
        });
      },
    });
  };

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="mb-10">
        <h1 className="text-3xl md:text-4xl font-bold tracking-tight mb-3">Settings</h1>
        <p className="text-muted-foreground text-lg">
          Manage integrations for your account.
        </p>
      </div>

      <div className="glass-panel p-6 sm:p-10 rounded-3xl">
        <div className="flex items-start gap-4 mb-8">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 shrink-0">
            <KeyRound className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold mb-1">DeepSeek AI Key</h2>
            <p className="text-sm text-muted-foreground">
              Bring your own DeepSeek API key to generate AI security analysis and
              paste-ready agent fix prompts on Deep scans using your own account. Stored
              encrypted — never shown again after saving.{" "}
              <a
                href="https://platform.deepseek.com/api_keys"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary inline-flex items-center gap-1 hover:underline"
              >
                Get a key <ExternalLink className="w-3 h-3" />
              </a>
            </p>
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center gap-2 text-muted-foreground text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading…
          </div>
        ) : keyStatus?.configured ? (
          <div className="flex items-center justify-between gap-4 flex-wrap bg-secondary/50 border border-white/5 rounded-2xl p-5">
            <div className="flex items-center gap-3">
              <ShieldCheck className="w-5 h-5 text-primary shrink-0" />
              <div>
                <div className="font-semibold">Key configured</div>
                <div className="text-sm text-muted-foreground font-mono">
                  sk-••••••••{keyStatus.last4}
                </div>
              </div>
            </div>
            <button
              type="button"
              onClick={handleRemove}
              disabled={deleteKey.isPending}
              className="flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-lg border border-red-500/20 text-red-400 hover:bg-red-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {deleteKey.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Trash2 className="w-4 h-4" />
              )}
              Remove
            </button>
          </div>
        ) : (
          <form onSubmit={handleSave} className="flex flex-col gap-4">
            <label htmlFor="deepseek-key" className="text-sm font-semibold">
              API Key
            </label>
            <div className="relative">
              <input
                id="deepseek-key"
                type={showKey ? "text" : "password"}
                placeholder="sk-..."
                value={apiKeyInput}
                onChange={(e) => setApiKeyInput(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                className="w-full bg-background border-2 border-white/10 rounded-xl py-3 pl-4 pr-12 font-mono text-sm focus:outline-none focus:border-primary focus:ring-4 focus:ring-primary/10 transition-all placeholder:text-muted-foreground/50"
              />
              <button
                type="button"
                onClick={() => setShowKey((v) => !v)}
                className="absolute inset-y-0 right-0 pr-4 flex items-center text-muted-foreground hover:text-foreground"
                tabIndex={-1}
              >
                {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>

            <div className="flex items-center gap-4 mt-2">
              <button
                type="submit"
                disabled={setKey.isPending || !apiKeyInput.trim()}
                className="px-6 py-3 bg-primary text-primary-foreground text-sm font-bold rounded-xl shadow-[0_0_20px_rgba(20,184,120,0.25)] hover:shadow-[0_0_30px_rgba(20,184,120,0.4)] disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center gap-2"
              >
                {setKey.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                Save Key
              </button>
              {setKey.isError && (
                <p className="text-red-400 text-sm">{getFriendlyError(setKey.error)}</p>
              )}
            </div>
          </form>
        )}
      </div>

      <div className="glass-panel p-6 sm:p-10 rounded-3xl mt-8 border border-red-500/20">
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
