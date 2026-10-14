import { describe, it, expect, afterEach } from "vitest";
import { metaForPath, applyPageMeta, registerChecks, type CheckMeta } from "./pageMeta";
import { isSpaRoute, setLearnCheckIds } from "./spaRoutes";

const CHECKS: CheckMeta[] = [
  {
    id: "hsts",
    title: "HSTS: what it is and how to fix it — SecScan.us",
    description: "HSTS is a response header that tells browsers to always use HTTPS.",
    name: "HTTP Strict Transport Security (HSTS)",
    what: "HSTS is a response header that tells browsers to always use HTTPS.",
    fix: "Send Strict-Transport-Security with a max-age of at least a year.",
  },
  {
    id: "csp-missing",
    title: "CSP: what it is and how to fix it — SecScan.us",
    description: "A Content-Security-Policy limits where a page may load code from.",
    name: "Missing Content-Security-Policy",
    what: "A Content-Security-Policy limits where a page may load code from.",
    fix: "Add a Content-Security-Policy header.",
  },
];

const SHELL = `<!doctype html><html><head>
<title>SecScan</title>
<meta name="description" content="Old." />
<meta name="robots" content="index, follow" />
<link rel="canonical" href="https://secscan.us/" />
<script type="application/ld+json">
{ "@context": "https://schema.org", "@graph": [
  { "@type": "Organization", "@id": "https://secscan.us/#organization", "name": "SecScan" },
  { "@type": "Person", "@id": "https://secscan.us/#founder", "name": "Founder" },
  { "@type": "WebPage", "@id": "https://secscan.us/#webpage", "url": "https://secscan.us/", "name": "Home" },
  { "@type": "FAQPage", "mainEntity": [] }
] }
</script>
</head><body></body></html>`;

function graphOf(html: string): Record<string, unknown>[] {
  const m = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/i.exec(html);
  if (!m?.[1]) throw new Error("no JSON-LD block");
  return (JSON.parse(m[1]) as { "@graph": Record<string, unknown>[] })["@graph"];
}

afterEach(() => {
  registerChecks([]);
  setLearnCheckIds(null);
});

describe("/learn/<id> routing", () => {
  it("serves the shell for a documented check and 404s any other id", () => {
    setLearnCheckIds(CHECKS.map((c) => c.id));
    expect(isSpaRoute("/learn/hsts")).toBe(true);
    expect(isSpaRoute("/learn/hsts/")).toBe(true);
    expect(isSpaRoute("/learn/not-a-check")).toBe(false);
    expect(isSpaRoute("/learn/hsts/extra")).toBe(false);
    expect(isSpaRoute("/learn/HSTS")).toBe(false);
  });

  it("lets a well-formed id through when the build wrote no list, but still refuses malformed ones", () => {
    setLearnCheckIds(null);
    expect(isSpaRoute("/learn/anything")).toBe(true);
    expect(isSpaRoute("/learn/..%2fadmin")).toBe(false);
    expect(isSpaRoute("/learn/a_b")).toBe(false);
  });

  it("leaves /learn itself alone", () => {
    setLearnCheckIds([]);
    expect(isSpaRoute("/learn")).toBe(true);
    expect(isSpaRoute("/learn/")).toBe(true);
  });
});

describe("/learn/<id> metadata", () => {
  it("uses the check's own title, description and canonical", () => {
    registerChecks(CHECKS);
    const out = applyPageMeta(SHELL, metaForPath("/learn/hsts")!);

    expect(out).toContain("<title>HSTS: what it is and how to fix it — SecScan.us</title>");
    expect(out).toContain('<link rel="canonical" href="https://secscan.us/learn/hsts" />');
    expect(out).toContain('content="index, follow"');
  });

  it("describes the page as an article with a Home > documentation > check trail and two questions", () => {
    registerChecks(CHECKS);
    const g = graphOf(applyPageMeta(SHELL, metaForPath("/learn/hsts")!));

    const page = g.find((n) => n["@type"] === "WebPage")!;
    const crumbs = (page["breadcrumb"] as { itemListElement: { name: string; item: string }[] }).itemListElement;
    expect(crumbs.map((c) => c.item)).toEqual(["https://secscan.us/", "https://secscan.us/learn", "https://secscan.us/learn/hsts"]);

    const article = g.find((n) => n["@type"] === "TechArticle")!;
    expect(article["url"]).toBe("https://secscan.us/learn/hsts");
    expect(article["author"]).toEqual({ "@id": "https://secscan.us/#founder" });

    const faqs = g.filter((n) => n["@type"] === "FAQPage");
    expect(faqs).toHaveLength(1);
    const qs = faqs[0]!["mainEntity"] as { name: string; acceptedAnswer: { text: string } }[];
    expect(qs.map((q) => q.name)).toEqual([
      "What is HTTP Strict Transport Security (HSTS)?",
      "How do I fix HTTP Strict Transport Security (HSTS)?",
    ]);
    expect(qs[0]!.acceptedAnswer.text).toBe(CHECKS[0]!.what);
    expect(qs[1]!.acceptedAnswer.text).toBe(CHECKS[0]!.fix);
  });

  it("gives each check its own metadata, not another's", () => {
    registerChecks(CHECKS);
    expect(metaForPath("/learn/csp-missing")!.title).toBe(CHECKS[1]!.title);
    expect(metaForPath("/learn/hsts")!.title).toBe(CHECKS[0]!.title);
  });

  it("marks an unknown id noindex and emits no structured data for it", () => {
    registerChecks(CHECKS);
    const meta = metaForPath("/learn/nope")!;
    expect(meta.noindex).toBe(true);
    expect(applyPageMeta(SHELL, meta)).not.toContain("application/ld+json");
  });

  it("leaves the /learn page's own metadata, and the home page, alone", () => {
    registerChecks(CHECKS);
    expect(metaForPath("/learn")!.title).toBe("Security Documentation — SecScan.us");
    expect(metaForPath("/")).toBeNull();
  });
});
