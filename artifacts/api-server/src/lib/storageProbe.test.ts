import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { runStorageProbe } from "./storageProbe.js";
import { useRouteSite } from "./routeSite.testkit";

/**
 * First tests for this module. Its only importer is scanner.ts, which has no
 * test file, so nothing exercised it — and it emits a High CWE-552.
 *
 * The distinction that matters: a bucket URL appearing in a page is normal
 * (that is how assets are served), and a bucket that refuses to list is
 * correctly configured. A finding requires the bucket to actually return a
 * listing. Everything below tests that line.
 *
 * The buckets are asked at a real web server on loopback (STORAGE_PROBE_ORIGIN, lib/routeSite.testkit.ts) that answers
 * every listing request the way the test says; the page still names the bucket's real provider address.
 */

const site = await useRouteSite();
beforeAll(() => { process.env["STORAGE_PROBE_ORIGIN"] = site.origin; });
afterAll(() => { delete process.env["STORAGE_PROBE_ORIGIN"]; });

function answerWith(body: string, ct = "application/xml", status = 200) {
  site.otherwise(() => ({ body, ct, status }));
}

const S3_LISTING = `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>example-backups</Name>
  <Contents><Key>logo.png</Key></Contents>
  <Contents><Key>backup/db-dump.sql</Key></Contents>
</ListBucketResult>`;

const S3_ACCESS_DENIED = `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`;

const pageWithS3 = '<html><body><img src="https://example-backups.s3.amazonaws.com/logo.png"></body></html>';

describe("runStorageProbe — a bucket that really lists", () => {
  it("reports a public S3 listing and counts the objects", async () => {
    answerWith(S3_LISTING);

    const vulns = await runStorageProbe("https://example.com/", pageWithS3);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.severity).toBe("high");
    expect(vulns[0]!.cweId).toBe("CWE-552");
    expect(vulns[0]!.name).toMatch(/example-backups/);
    expect(vulns[0]!.evidence).toMatch(/2 object/);
  });

  it("reports an Azure container that enumerates", async () => {
    answerWith("<?xml version=\"1.0\"?><EnumerationResults><Blobs><Blob><Name>a.txt</Name></Blob></Blobs></EnumerationResults>");

    const page = '<html><body><a href="https://exampleacct.blob.core.windows.net/media/a.txt">x</a></body></html>';
    const vulns = await runStorageProbe("https://example.com/", page);
    expect(vulns.some((v) => /Azure/i.test(v.name) && v.severity === "high")).toBe(true);
  });
});

describe("runStorageProbe — a bucket that refuses is not a finding", () => {
  it("ignores AccessDenied, which is the correct configuration", async () => {
    // A locked-down bucket answers with an Error document. Reporting that as a
    // public listing would flag every correctly configured bucket on the page.
    answerWith(S3_ACCESS_DENIED, "application/xml", 403);

    expect(await runStorageProbe("https://example.com/", pageWithS3)).toEqual([]);
  });

  it("ignores an AccessDenied body that somehow arrives with HTTP 200", async () => {
    answerWith(S3_ACCESS_DENIED, "application/xml", 200);

    expect(await runStorageProbe("https://example.com/", pageWithS3)).toEqual([]);
  });

  it("ignores a 404 for a bucket that does not exist", async () => {
    answerWith("<Error><Code>NoSuchBucket</Code></Error>", "application/xml", 404);

    expect(await runStorageProbe("https://example.com/", pageWithS3)).toEqual([]);
  });

  it("ignores an HTML page returned in place of a listing", async () => {
    answerWith("<html><body>Sign in to continue</body></html>", "text/html", 200);

    expect(await runStorageProbe("https://example.com/", pageWithS3)).toEqual([]);
  });
});

describe("runStorageProbe — a listable bucket that is not shown to be the site's", () => {
  const listing = (...keys: string[]) =>
    `<ListBucketResult>${keys.map((k) => `<Contents><Key>${k}</Key></Contents>`).join("")}</ListBucketResult>`;
  const otherPage = '<html><body><a href="https://open-census-data.s3.amazonaws.com/2020.csv">data</a></body></html>';

  it("a third-party public dataset bucket is a hedged LOW, not a HIGH against the customer", async () => {
    answerWith(listing("2020.csv", "2021.csv"));
    const vulns = await runStorageProbe("https://example.com/", otherPage);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.severity).toBe("low");
    expect(vulns[0]!.confidence).toBeLessThan(85);
    expect(vulns[0]!.description).toMatch(/third party|Verify/i);
  });

  it("a bucket listing only images/css/js/fonts is INFO even when the name matches the site", async () => {
    answerWith(listing("img/logo.png", "app.js", "site.css", "fonts/a.woff2"));
    const page = '<html><img src="https://example-assets.s3.amazonaws.com/img/logo.png"></html>';
    const vulns = await runStorageProbe("https://www.example.com/", page);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.severity).toBe("info");
  });

  it("the site's own bucket holding a non-asset file is still HIGH", async () => {
    answerWith(listing("img/logo.png", "backup/db-dump.sql"));
    const page = '<html><img src="https://example-assets.s3.amazonaws.com/img/logo.png"></html>';
    const vulns = await runStorageProbe("https://www.example.com/", page);
    expect(vulns[0]!.severity).toBe("high");
    expect(vulns[0]!.confidence).toBeGreaterThanOrEqual(85);
  });
});

describe("runStorageProbe — nothing to probe", () => {
  it("makes no findings when the page references no buckets", async () => {
    // Also asserts we do not fabricate a bucket name out of an ordinary page.
    answerWith(S3_LISTING);

    const page = '<html><body><img src="/static/logo.png"></body></html>';
    expect(await runStorageProbe("https://example.com/", page)).toEqual([]);
  });

  it("does not treat an unrelated amazonaws URL as a bucket", async () => {
    answerWith(S3_LISTING);

    const page = '<html><body><a href="https://console.aws.amazon.com/s3">console</a></body></html>';
    expect(await runStorageProbe("https://example.com/", page)).toEqual([]);
  });
});
