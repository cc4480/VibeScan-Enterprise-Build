import { describe, it, expect } from "vitest";
import { matchCvesToTechnologies, type NvdCve } from "./cveMonitor";

/**
 * The monitor's CVE matching had no tests at all, and the defect that motivated
 * these is the reason why that mattered: it failed silently, in the direction
 * nobody notices.
 *
 * scanner.ts enriches detected technologies with versions for display
 * ("Nginx" -> "Nginx 1.18.0"); TECH_KEYWORDS is keyed on the bare name and the
 * lookup is exact. So any technology whose version the scanner successfully
 * detected was dropped from CVE matching without an error or a log — and the
 * seven that get enriched (Angular, Apache, IIS, LiteSpeed, Nginx, OpenResty,
 * PHP) are precisely the ones a CVE feed is worth running for.
 *
 * A daily job that quietly matches nothing looks exactly like a daily job that
 * found nothing to report, which is why this is tested by shape rather than by
 * watching production stay quiet.
 */

function cve(id: string, description: string): NvdCve {
  return { id, description, severity: "high", cvssScore: 7.5, publishedDate: "2026-01-01T00:00:00.000" };
}

const NGINX_CVE = cve(
  "CVE-2021-23017",
  "A security issue in nginx resolver was identified, which might allow an attacker " +
    "to cause 1-byte memory overwrite by using a specially crafted DNS response.",
);

const RAILS_CVE = cve(
  "CVE-2026-00001",
  "A deserialization flaw in Ruby on Rails ActiveSupport allows remote code execution.",
);

const CLOUDFRONT_CVE = cve(
  "CVE-2026-00002",
  "A request-smuggling issue in Amazon CloudFront allows cache poisoning.",
);

const UNRELATED_CVE = cve(
  "CVE-2026-09999",
  "A buffer overflow in an industrial railway signalling controller allows denial of service.",
);

describe("matchCvesToTechnologies — version-enriched technology names", () => {
  it("matches a technology the scanner detected a version for", () => {
    // The regression. This is the exact string shape scanner.ts produces.
    const hits = matchCvesToTechnologies(["Nginx 1.18.0"], [NGINX_CVE]);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.cve.id).toBe("CVE-2021-23017");
  });

  it("still matches the bare name, which is what the keyword table is keyed on", () => {
    expect(matchCvesToTechnologies(["Nginx"], [NGINX_CVE])).toHaveLength(1);
  });

  it("reports the technology as it was given, so the alert keeps the version", () => {
    const [hit] = matchCvesToTechnologies(["Nginx 1.18.0"], [NGINX_CVE]);
    // Looked up bare, reported verbatim — an alert saying "Nginx" when the scan
    // saw 1.18.0 throws away the one detail that makes it actionable.
    expect(hit!.matchedTech).toBe("Nginx 1.18.0");
  });

  it("handles every version shape the fingerprinter can append", () => {
    for (const tech of ["Nginx 1.18.0", "Nginx 1.18", "Nginx v1.18.0", "Nginx 1.18.0-1"]) {
      expect(matchCvesToTechnologies([tech], [NGINX_CVE]), tech).toHaveLength(1);
    }
  });
});

describe("matchCvesToTechnologies — names that contain spaces", () => {
  it("does not truncate a multi-word technology name", () => {
    // Stripping at the first space instead of at a trailing version would turn
    // this into "Ruby", which is not a key and would silently match nothing.
    expect(matchCvesToTechnologies(["Ruby on Rails"], [RAILS_CVE])).toHaveLength(1);
  });

  it("does not truncate a multi-word name that also carries a version", () => {
    expect(matchCvesToTechnologies(["Ruby on Rails 7.1.3"], [RAILS_CVE])).toHaveLength(1);
  });

  it("keeps a name whose last word is not a version", () => {
    expect(matchCvesToTechnologies(["AWS CloudFront"], [CLOUDFRONT_CVE])).toHaveLength(1);
  });
});

describe("matchCvesToTechnologies — keys must match what the fingerprinter emits", () => {
  it("matches Express.js, the string techFingerprint.ts actually produces", () => {
    const expressCve = cve("CVE-2026-00003", "A path traversal in express.js static middleware.");
    expect(matchCvesToTechnologies(["Express.js"], [expressCve])).toHaveLength(1);
  });
});

describe("matchCvesToTechnologies — staying quiet", () => {
  it("returns nothing when no keyword appears in the description", () => {
    expect(matchCvesToTechnologies(["Nginx 1.18.0"], [RAILS_CVE])).toHaveLength(0);
  });

  it("returns nothing for a technology with no keyword entry", () => {
    expect(matchCvesToTechnologies(["Bootstrap 5.3.0"], [NGINX_CVE])).toHaveLength(0);
  });

  it("returns nothing for an empty technology list", () => {
    expect(matchCvesToTechnologies([], [NGINX_CVE])).toHaveLength(0);
  });

  it("does not report the same CVE twice for the same technology", () => {
    expect(matchCvesToTechnologies(["Nginx", "Nginx"], [NGINX_CVE])).toHaveLength(1);
  });
});

describe("matchCvesToTechnologies — known limits, asserted so they stay visible", () => {
  it("matches on prose alone, with no version awareness", () => {
    // A current, patched nginx still matches a CVE about an old one. This is a
    // property of keyword matching, not a bug in it — but it is the reason an
    // alert must never be worded as "your version is vulnerable".
    const hits = matchCvesToTechnologies(["Nginx 1.99.0"], [NGINX_CVE]);
    expect(hits).toHaveLength(1);
  });

  it("matches a generic keyword anywhere in the description", () => {
    // "railway" is an ordinary English word, and this CVE is about rail
    // signalling hardware. Pinned so that if the keyword list is ever
    // tightened, the change is deliberate and this test is what flags it.
    expect(matchCvesToTechnologies(["Railway"], [UNRELATED_CVE])).toHaveLength(1);
  });
});
