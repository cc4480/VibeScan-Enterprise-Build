import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

/**
 * The anonymous identity.
 *
 * This UUID *is* the user as far as the API is concerned, so the behaviour that
 * matters is stability: a token that changed between calls would silently strip
 * someone of their scan history, and one that failed to persist would do the
 * same on the next page load.
 */

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** A localStorage that can be told to misbehave, as a real one does. */
function fakeStorage(opts: { throwOnGet?: boolean; throwOnSet?: boolean } = {}) {
  const map = new Map<string, string>();
  return {
    store: map,
    getItem(key: string) {
      if (opts.throwOnGet) throw new Error("SecurityError");
      return map.get(key) ?? null;
    },
    setItem(key: string, value: string) {
      if (opts.throwOnSet) throw new Error("QuotaExceededError");
      map.set(key, value);
    },
  };
}

async function loadFresh() {
  vi.resetModules();
  return import("./auth-token.js");
}

beforeEach(() => {
  vi.stubGlobal("localStorage", fakeStorage());
  vi.stubGlobal("crypto", globalThis.crypto);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("getOrCreateToken", () => {
  it("mints a v4 UUID on first use", async () => {
    const { getOrCreateToken } = await loadFresh();
    expect(getOrCreateToken()).toMatch(UUID_V4);
  });

  it("returns the same token on every call", async () => {
    const { getOrCreateToken } = await loadFresh();
    expect(getOrCreateToken()).toBe(getOrCreateToken());
  });

  it("persists it, so a reload keeps the same identity", async () => {
    const storage = fakeStorage();
    vi.stubGlobal("localStorage", storage);

    const first = await loadFresh();
    const token = first.getOrCreateToken();

    // Fresh module, same storage — this is what a page reload looks like.
    const second = await loadFresh();
    expect(second.getOrCreateToken()).toBe(token);
  });

  it("reuses an existing valid token rather than replacing it", async () => {
    const existing = "3b241101-e2bb-4255-8caf-4136c566a962";
    const storage = fakeStorage();
    storage.store.set("vibescan_client_token", existing);
    vi.stubGlobal("localStorage", storage);

    const { getOrCreateToken } = await loadFresh();
    expect(getOrCreateToken()).toBe(existing);
  });

  it("replaces a stored value that is not a valid UUID", async () => {
    // A corrupt entry must not be sent as an identity: the API rejects
    // anything that is not a v4 UUID, which would look like being logged out.
    const storage = fakeStorage();
    storage.store.set("vibescan_client_token", "not-a-uuid");
    vi.stubGlobal("localStorage", storage);

    const { getOrCreateToken } = await loadFresh();
    expect(getOrCreateToken()).toMatch(UUID_V4);
  });

  it("stays stable when localStorage cannot be written", async () => {
    // Private browsing and storage-blocking settings both do this. Falling back
    // to memory keeps the identity stable for the life of the page rather than
    // minting a new user on every call.
    vi.stubGlobal("localStorage", fakeStorage({ throwOnSet: true }));

    const { getOrCreateToken } = await loadFresh();
    const token = getOrCreateToken();
    expect(token).toMatch(UUID_V4);
    expect(getOrCreateToken()).toBe(token);
  });

  it("stays stable when localStorage cannot be read", async () => {
    vi.stubGlobal("localStorage", fakeStorage({ throwOnGet: true }));

    const { getOrCreateToken } = await loadFresh();
    const token = getOrCreateToken();
    expect(getOrCreateToken()).toBe(token);
  });
});

describe("getAuthHeaders", () => {
  it("produces a bearer header carrying the token", async () => {
    const { getAuthHeaders, getOrCreateToken } = await loadFresh();
    const token = getOrCreateToken();
    expect(getAuthHeaders()).toEqual({ Authorization: `Bearer ${token}` });
  });
});
