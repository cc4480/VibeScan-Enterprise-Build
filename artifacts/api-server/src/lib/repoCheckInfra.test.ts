import { describe, it, expect } from "vitest";
import { infraFindings, dockerHygieneFindings, actionsHygieneFindings, isInfraPath } from "./repoCheckInfra";
import type { RepoFile, RepoRef } from "./repoFinding";

const ref: RepoRef = { owner: "acme", repo: "app" };
const f = (path: string, content: string): RepoFile => ({ path, content });
const names = (list: Array<{ name: string }>) => list.map((v) => v.name);

describe("Firebase rules", () => {
  it("flags write access for everyone as critical, and the 30-day test mode the same way", () => {
    const open = infraFindings(f("firestore.rules", `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}`), ref);
    expect(names(open)).toEqual(["Firestore Rules Let Anyone Write", "Firestore Rules Let Anyone Read"]);
    expect(open[0]!.severity).toBe("critical");
    expect(open[1]!.severity).toBe("high"); // a wildcard path covers every document
    const testMode = infraFindings(f("firestore.rules", `service cloud.firestore { match /databases/{d}/documents { match /{document=**} { allow read, write: if request.time < timestamp.date(2026, 11, 30); } } }`), ref);
    expect(names(testMode)).toContain("Firestore Rules Let Anyone Write");
    expect(testMode[0]!.evidence).toMatch(/test mode/);
  });

  it("rates a public read on one named path lower, and says Storage for storage rules", () => {
    const f1 = infraFindings(f("storage.rules", `service firebase.storage { match /b/{bucket}/o { match /public/{file} { allow read: if true; allow write: if request.auth != null; } } }`), ref);
    expect(names(f1)).toEqual(["Cloud Storage Rules Let Anyone Read"]);
    expect(f1[0]!.severity).toBe("medium");
  });

  it("clean twin: rules that require sign-in and ownership report nothing, and a commented-out open rule does not count", () => {
    const clean = `service cloud.firestore {\n  match /databases/{database}/documents {\n    // allow read, write: if true;\n    match /users/{uid} {\n      allow read, write: if request.auth != null && request.auth.uid == uid;\n    }\n  }\n}`;
    expect(infraFindings(f("firestore.rules", clean), ref)).toEqual([]);
  });

  it("reads Realtime Database rules, including string conditions and nested paths", () => {
    const open = infraFindings(f("database.rules.json", JSON.stringify({ rules: { ".read": true, ".write": "true" } })), ref);
    expect(open[0]).toMatchObject({ name: "Realtime Database Rules Let Anyone Write", severity: "critical" });
    expect(infraFindings(f("database.rules.json", JSON.stringify({ rules: { posts: { ".read": true } } })), ref)[0]).toMatchObject({ name: "Realtime Database Rules Let Anyone Read" });
    expect(infraFindings(f("database.rules.json", JSON.stringify({ rules: { ".read": "now < 1700000000000" } })), ref)).toHaveLength(1);
    expect(infraFindings(f("database.rules.json", JSON.stringify({ rules: { users: { "$uid": { ".read": "auth != null && auth.uid === $uid", ".write": "auth.uid === $uid" } } } })), ref)).toEqual([]);
    expect(infraFindings(f("database.rules.json", "not json"), ref)).toEqual([]);
  });
});

describe("docker-compose", () => {
  it("flags a privileged service, the Docker socket, and a database port open on every interface", () => {
    const body = `services:\n  db:\n    image: postgres:16\n    ports:\n      - "5432:5432"\n  agent:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n`;
    expect(names(infraFindings(f("docker-compose.yml", body), ref))).toEqual(["Compose Service Runs Privileged", "Compose Service Mounts the Docker Socket", "Compose Publishes a Database Port to Every Network Interface"]);
  });

  it("clean twin: a loopback-bound database port, no privilege, no socket", () => {
    const body = `services:\n  db:\n    image: postgres:16\n    ports:\n      - "127.0.0.1:5432:5432"\n  web:\n    ports:\n      - "8080:80"\n    # privileged: true\n`;
    expect(infraFindings(f("compose.yaml", body), ref)).toEqual([]);
  });
});

describe("Dockerfile hygiene", () => {
  it("flags a download piped to a shell, a missing USER and an unpinned base", () => {
    const bad = `FROM node:latest\nRUN curl -fsSL https://example.com/install.sh | bash\nCMD ["node","server.js"]\n`;
    expect(names(dockerHygieneFindings(f("Dockerfile", bad), ref))).toEqual(["Dockerfile Pipes a Download Into a Shell", "Container Runs as Root", "Dockerfile Base Image Is Not Pinned"]);
  });

  it("clean twin: pinned tag, non-root user, no pipe to a shell", () => {
    const good = `FROM node:22.11-alpine AS build\nRUN npm ci\nFROM node:22.11-alpine\nCOPY --from=build /app /app\nUSER node\nCMD ["node","server.js"]\n`;
    expect(dockerHygieneFindings(f("Dockerfile", good), ref)).toEqual([]);
  });

  it("looks at the last stage for USER, and does not treat a build stage name as an unpinned image", () => {
    const multi = `FROM golang:1.22 AS builder\nRUN go build -o /app\nFROM builder\nUSER 1000\nCMD ["/app"]\n`;
    expect(dockerHygieneFindings(f("Dockerfile", multi), ref)).toEqual([]);
    expect(names(dockerHygieneFindings(f("Dockerfile", `FROM python:3.12-slim\nUSER root\nCMD ["python"]\n`), ref))).toEqual(["Container Runs as Root"]);
    expect(dockerHygieneFindings(f("Dockerfile", `FROM gcr.io/distroless/nodejs22:nonroot\nCMD ["server.js"]\n`), ref)).toEqual([]);
  });
});

describe("GitHub Actions pinning", () => {
  it("flags third-party actions on a tag, not GitHub's own, and not a full commit SHA", () => {
    const wf = `jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: tj-actions/changed-files@v44\n      - uses: acme/deploy@0123456789abcdef0123456789abcdef01234567 # v2\n      - uses: ./local-action\n`;
    const found = actionsHygieneFindings(f(".github/workflows/ci.yml", wf), ref);
    expect(names(found)).toEqual(["GitHub Actions Uses Third-Party Actions Pinned to a Mutable Tag"]);
    expect(found[0]!.evidence).toContain("tj-actions/changed-files@v44");
    expect(found[0]!.evidence).not.toContain("actions/checkout");
    expect(found[0]!.evidence).not.toContain("acme/deploy");
  });

  it("notes `secrets: inherit` as information, and reports nothing for a pinned, minimal workflow", () => {
    const inherit = actionsHygieneFindings(f(".github/workflows/call.yml", `jobs:\n  x:\n    uses: ./.github/workflows/build.yml\n    secrets: inherit\n`), ref);
    expect(inherit[0]).toMatchObject({ severity: "info" });
    expect(actionsHygieneFindings(f(".github/workflows/ok.yml", `jobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n`), ref)).toEqual([]);
  });
});

it("knows which files it reads", () => {
  expect(isInfraPath("deploy/docker-compose.prod.yml")).toBe(true);
  expect(isInfraPath("firebase/firestore.rules")).toBe(true);
  expect(isInfraPath("src/app.ts")).toBe(false);
});
