/**
 * The OpenAPI description of the REST API, served at /api/v1/openapi.json.
 *
 * Written by hand (the routes are few) and kept honest by apiV1Spec.test.ts, which
 * fails if a route exists that the spec does not describe, or the reverse.
 */
const error = { $ref: "#/components/schemas/Error" };
const errorResponses = {
  "401": { description: "Missing, invalid or wrong-scope token", content: { "application/json": { schema: error } } },
  "429": { description: "Rate limited; see Retry-After", content: { "application/json": { schema: error } } },
};

export const API_V1_SPEC = {
  openapi: "3.1.0",
  info: {
    title: "SecScan API",
    version: "1.0.0",
    description:
      "Scan a URL you own or are authorised to test, and read the result. Authenticate with a token whose scope is API " +
      "(Settings → API). Active tests (injection, access control, SSRF) run only on domains you have verified; " +
      "a report says which tests ran and which were skipped, and a clean grade says nothing about skipped areas.",
  },
  servers: [{ url: "https://secscan.us/api/v1" }],
  security: [{ bearer: [] }],
  paths: {
    "/me": {
      get: { summary: "Who the token belongs to", responses: { "200": { description: "The account" }, ...errorResponses } },
    },
    "/scans": {
      post: {
        summary: "Start a scan",
        description: "Counts against your free scans, or your plan if you have one (an unlimited plan is not counted), exactly as the website does.",
        requestBody: {
          required: true,
          content: { "application/json": { schema: { type: "object", required: ["url"], properties: { url: { type: "string", example: "https://staging.example.com" }, githubRepo: { type: "string", description: "Optional. A public GitHub repository to also read for committed secrets, e.g. https://github.com/owner/repo. Only GitHub is contacted for it, never the scanned site.", example: "https://github.com/owner/repo" } } } } },
        },
        responses: {
          "202": { description: "Queued. Poll GET /scans/{id}, or pass ?wait=60 there." },
          "400": { description: "Invalid request or a URL that may not be scanned", content: { "application/json": { schema: error } } },
          "402": { description: "No scans left", content: { "application/json": { schema: error } } },
          ...errorResponses,
        },
      },
      get: {
        summary: "Recent scans",
        parameters: [{ name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 50, default: 20 } }],
        responses: { "200": { description: "Your scans, newest first" }, ...errorResponses },
      },
    },
    "/scans/{id}": {
      get: {
        summary: "Status and a short summary of a scan",
        description:
          "Once complete: grade, risk score, finding counts by severity, scanNotes (the scan's own remarks about itself, such as a skipped test " +
          "or a sign-in page that answered instead of the app, which are not findings and are not in the counts), and coverage (tests that ran, were skipped or failed). " +
          "With wait (seconds, max 60) the call holds until the scan finishes.",
        parameters: [
          { name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } },
          { name: "wait", in: "query", schema: { type: "integer", minimum: 0, maximum: 60 } },
        ],
        responses: { "200": { description: "The scan" }, "404": { description: "No such scan (or not yours)", content: { "application/json": { schema: error } } }, ...errorResponses },
      },
    },
    "/scans/{id}/report": {
      get: {
        summary: "The full report",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
        responses: {
          "200": { description: "Findings with evidence and fixes, what the scan tested, and compliance mapping" },
          "409": { description: "The scan has not finished", content: { "application/json": { schema: error } } },
          "404": { description: "No such scan (or not yours)", content: { "application/json": { schema: error } } },
          ...errorResponses,
        },
      },
    },
    "/scans/{id}/sarif": {
      get: {
        summary: "The findings as SARIF 2.1.0",
        description:
          "For GitHub code scanning and other CI tools. A scan of a running site has no file or line, so each result is located at the URL it was found at.",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
        responses: {
          "200": { description: "A SARIF 2.1.0 log", content: { "application/sarif+json": { schema: { type: "object" } } } },
          "409": { description: "The scan has not finished", content: { "application/json": { schema: error } } },
          "404": { description: "No such scan (or not yours)", content: { "application/json": { schema: error } } },
          ...errorResponses,
        },
      },
    },
    "/openapi.json": {
      get: { summary: "This document", security: [], responses: { "200": { description: "OpenAPI 3.1" } } },
    },
  },
  components: {
    securitySchemes: { bearer: { type: "http", scheme: "bearer", description: "A token with scope API. Prefix: ssk_" } },
    schemas: {
      Error: {
        type: "object",
        required: ["error"],
        properties: { error: { type: "object", required: ["code", "message"], properties: { code: { type: "string" }, message: { type: "string" } } } },
      },
    },
  },
} as const;
