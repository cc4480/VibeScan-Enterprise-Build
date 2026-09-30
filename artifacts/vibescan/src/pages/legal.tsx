import { Shield, FileText } from "lucide-react";
import { useSeo } from "@/lib/seo";
import { LAST_UPDATED, CONTACT } from "./legal-shared";
import { Privacy } from "./legal-privacy";
import { Terms } from "./legal-terms";

export default function LegalPage({ kind }: { kind: "privacy" | "terms" }) {
  const isPrivacy = kind === "privacy";
  const Icon = isPrivacy ? Shield : FileText;
  const title = isPrivacy ? "Privacy Policy" : "Terms of Service";

  useSeo({
    title: `${title} — SecScan.us`,
    description: isPrivacy
      ? "What SecScan collects, why, and who else sees it."
      : "The terms that apply when you use SecScan, including what you may scan.",
  });

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="flex items-center gap-3 mb-2">
        <div className="w-11 h-11 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 shrink-0">
          <Icon className="w-5 h-5 text-primary" />
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">{title}</h1>
      </div>
      <p className="text-sm text-muted-foreground mb-10">Last updated {LAST_UPDATED[kind]}</p>

      {isPrivacy ? <Privacy /> : <Terms />}

      <p className="text-xs text-muted-foreground border-t border-white/10 pt-6">
        Questions about this page: {CONTACT}
      </p>
    </div>
  );
}