/** The signed-in account menu and the breadcrumb labels. */
import { Link } from "wouter";
import { LogOut, LogIn } from "lucide-react";
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useGetCurrentAuthUser } from "@workspace/api-client-react";
import { cn } from "@/lib/utils";
import { signOut } from "@/lib/account-api";

/**
 * Visible breadcrumbs for the public subpages. The names must match the
 * BreadcrumbList JSON-LD the server writes for the same paths
 * (artifacts/api-server/src/lib/pageMeta.ts) — Google expects the two to agree.
 */
export const BREADCRUMBS: Record<string, string> = {
  "/learn": "Security documentation",
  "/privacy": "Privacy policy",
  "/terms": "Terms of service",
  "/bot": "SecScan bot",
  "/about": "About",
};

/**
 * Sign-in control.
 *
 * Accounts are additive here, not a gate: an anonymous visitor is still a real
 * user with real scans, so this offers to preserve that history rather than
 * demanding a login. A signed-in account is the one with an email — anonymous
 * identities have none.
 */
export function AccountNav({
  // The mobile menu stacks full-width rows; the desktop bar is a tight inline
  // cluster. Same control, and it has to appear in both — rendering it only in
  // the desktop nav left phone users with no way to reach /sign-in at all.
  mobile = false,
  onNavigate,
}: {
  mobile?: boolean;
  onNavigate?: () => void;
} = {}) {
  const { data } = useGetCurrentAuthUser();
  const queryClient = useQueryClient();
  const [signingOut, setSigningOut] = useState(false);
  const email = data?.user?.email ?? null;

  if (!email) {
    return (
      <Link
        href="/sign-in"
        onClick={onNavigate}
        className={
          mobile
            ? "px-4 py-2 text-foreground font-medium rounded-lg hover:bg-secondary flex items-center gap-2"
            : "text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
        }
      >
        {mobile ? <><LogIn className="w-4 h-4" /> Sign in</> : "Sign in"}
      </Link>
    );
  }

  async function handleSignOut() {
    setSigningOut(true);
    try {
      await signOut();
    } finally {
      // Refetch regardless: on success the identity changed, and on failure the
      // displayed state should still be re-read from the server rather than
      // guessed at.
      await queryClient.invalidateQueries();
      setSigningOut(false);
      onNavigate?.();
    }
  }

  return (
    <div className={mobile ? "flex flex-col gap-1" : "flex items-center gap-3"}>
      <span
        className={cn(
          "text-sm text-muted-foreground truncate",
          mobile ? "px-4 py-1" : "max-w-[12rem] 2xl:max-w-[16rem]",
        )}
        title={email}
      >
        {email}
      </span>
      <button
        type="button"
        onClick={handleSignOut}
        disabled={signingOut}
        className={
          mobile
            ? "px-4 py-2 text-foreground font-medium rounded-lg hover:bg-secondary flex items-center gap-2 disabled:opacity-60"
            : "flex items-center gap-1.5 text-sm font-medium text-muted-foreground hover:text-foreground disabled:opacity-60 transition-colors"
        }
      >
        <LogOut className={mobile ? "w-4 h-4" : "w-3.5 h-3.5"} />
        {signingOut ? "Signing out…" : "Sign out"}
      </button>
    </div>
  );
}
