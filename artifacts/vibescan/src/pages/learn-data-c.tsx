import type { Category } from "./learn-types";
import { Database, Wifi } from "lucide-react";

/** Learn-page categories: Supabase and network. */
export const LEARN_CATEGORIES_C: Category[] = [
  {
    id: "supabase",
    label: "Supabase & BaaS",
    description: "Supabase RLS, Firebase rules, PocketBase, and Appwrite access control checks.",
    icon: Database,
    checks: [
      {
        id: "supabase-rls",
        title: "Supabase Row Level Security (RLS) Not Enabled",
        shortTitle: "Supabase RLS",
        severity: "critical",
        cweId: "CWE-284",
        cvssScore: 9.8,
        owasp: "A01",
        what: "Supabase provides a public JavaScript client that connects directly to your PostgreSQL database. Row Level Security (RLS) is PostgreSQL's built-in mechanism for restricting which rows a user can read, insert, update, or delete based on security policies.",
        why: "If RLS is not enabled on a Supabase table, any user with your anon key (which is public by default — embedded in your frontend) can query the entire table with no restrictions. In many vibe-coded apps, this means any visitor can read all user data, all records, and potentially delete or modify them. This is arguably the most common critical vulnerability in AI-generated Supabase apps.",
        howTested: "SecScan extracts the Supabase project URL from your app's JavaScript, then makes an unauthenticated REST API request to known table endpoints. If the response returns rows with HTTP 200, RLS is not enabled on those tables. This is the same request an attacker would make.",
        fix: "Enable RLS on every Supabase table and write policies that restrict access to the authenticated user's own rows.",
        fixCode: `-- Step 1: Enable RLS on each table (run in Supabase SQL editor)
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
-- Repeat for every table

-- Step 2: Create policies that match your access rules

-- Allow users to read only their own profile
CREATE POLICY "Users can view own profile"
ON profiles FOR SELECT
USING (auth.uid() = user_id);

-- Allow users to update only their own profile
CREATE POLICY "Users can update own profile"
ON profiles FOR UPDATE
USING (auth.uid() = user_id);

-- Allow public read of published posts
CREATE POLICY "Anyone can read published posts"
ON posts FOR SELECT
USING (published = true);

-- Allow authors to manage their own posts
CREATE POLICY "Authors can manage own posts"
ON posts FOR ALL
USING (auth.uid() = author_id);`,
        fixCodeLang: "sql",
        learnMore: "https://supabase.com/docs/guides/database/postgres/row-level-security",
      },
    ],
  },
  {
    id: "network",
    label: "Network & DNS",
    description: "Email security records, DNS configuration, and exposed network services.",
    icon: Wifi,
    checks: [
      {
        id: "spf",
        title: "Missing or Weak SPF Record",
        shortTitle: "SPF Record",
        severity: "high",
        cweId: "CWE-345",
        cvssScore: 7.5,
        owasp: "A05",
        what: "SPF (Sender Policy Framework) is a DNS TXT record that lists which mail servers are authorised to send email on behalf of your domain. Receiving mail servers check SPF to detect forged sender addresses.",
        why: "Without SPF, anyone can send email that appears to come from your domain — enabling phishing campaigns, business email compromise, and spam. Attackers craft convincing emails with your domain as the sender to trick recipients into revealing credentials or authorising payments.",
        howTested: "SecScan queries the DNS TXT record for your apex domain via Cloudflare DoH. Missing SPF is flagged High. Permissive +all (allows all senders) is flagged Critical.",
        fix: "Publish an SPF record that lists your authorised sending sources and ends with -all to reject unauthorised senders.",
        fixCode: `# Add a TXT record to your DNS — example for Google Workspace + SendGrid:
v=spf1 include:_spf.google.com include:sendgrid.net -all

# Breaking it down:
# v=spf1              — SPF version
# include:_spf.google.com — authorise Google's mail servers
# include:sendgrid.net    — authorise SendGrid
# -all                    — REJECT all other senders (hard fail)
# ~all                    — SOFT FAIL others (less strict, still common)

# Check your record with:
dig TXT yourdomain.com | grep spf`,
        fixCodeLang: "nginx",
        learnMore: "https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/",
      },
      {
        id: "dmarc",
        title: "Missing or Weak DMARC Policy",
        shortTitle: "DMARC Policy",
        severity: "high",
        cweId: "CWE-345",
        cvssScore: 7.5,
        owasp: "A05",
        what: "DMARC (Domain-based Message Authentication, Reporting & Conformance) builds on SPF and DKIM to tell receiving mail servers what to do with messages that fail authentication — reject, quarantine, or do nothing.",
        why: "SPF and DKIM alone don't prevent spoofing of the human-visible From address. DMARC ties the SPF/DKIM results to the header From domain and specifies enforcement. Without DMARC, authenticated SPF/DKIM emails can still be spoofed at the UI level.",
        howTested: "SecScan queries _dmarc.yourdomain.com via DNS. Missing DMARC is High. p=none (monitoring only, no enforcement) is Medium.",
        fix: "Publish a DMARC record and gradually move to p=reject after monitoring with aggregate reports.",
        fixCode: `# Add TXT record at _dmarc.yourdomain.com

# Start with monitoring (p=none) to see who's sending on your behalf:
v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com

# After reviewing reports, tighten to quarantine:
v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com; pct=100

# Full enforcement — reject all failing messages:
v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com; adkim=s; aspf=s`,
        fixCodeLang: "nginx",
        learnMore: "https://dmarc.org/overview/",
      },
    ],
  },
];
