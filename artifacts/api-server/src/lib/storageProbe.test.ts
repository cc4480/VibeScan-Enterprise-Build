import { describe, it, expect, afterEach, vi } from "vitest";
import { runStorageProbe } from "./storageProbe.js";

/**
 * First tests for this module. Its only importer is scanner.ts, which has no
 * test file, so nothing exercised it — and it emits a High CWE-552.
 *
 * The distinction that matters: a bucket URL appearing in a page is normal
 * (that is how assets are served), and a bucket that refuses to list is
 * correctly configured. A finding requires the bucket to actually return a
 * listing. Everything below tests that line.
 */

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

function answerWith(body: string, ct = "application/xml", status = 200) {
  globalThis.fetch = (async () =>
    new Response(body, { status, headers: { "content-type": ct } })) as typeof fetch;
}

const S3_LISTING = `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>assets-bucket</Name>
  <Contents><Key>logo.png</Key></Contents>
  <Contents><Key>backup/db-dump.sql</Key></Contents>
</ListBucketResult>`;

const S3_ACCESS_DENIED = `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`;

const pageWithS3 = '<html><body><img src="https://assets-bucket.s3.amazonaws.com/logo.png"></body></html>';

describe("runStorageProbe — a bucket that really lists", () => {
  it("reports a public S3 listing and counts the objects", async () => {
    answerWith(S3_LISTING);

    const vulns = await runStorageProbe("https://example.com/", pageWithS3);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.severity).toBe("high");
    expect(vulns[0]!.cweId).toBe("CWE-552");
    expect(vulns[0]!.name).toMatch(/assets-bucket/);
    expect(vulns[0]!.evidence).toMatch(/2 items/);
  });

  it("reports an Azure container that enumerates", async () => {
    answerWith("<?xml version=\"1.0\"?><EnumerationResults><Blobs><Blob><Name>a.txt</Name></Blob></Blobs></EnumerationResults>");

    const page = '<html><body><a href="https://acct.blob.core.windows.net/media/a.txt">x</a></body></html>';
    const vulns = await runStorageProbe("https://example.com/", page);
    expect(vulns.some((v) => /Azure/i.test(v.name))).toBe(true);
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
