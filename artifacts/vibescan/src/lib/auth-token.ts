const TOKEN_KEY = "vibescan_client_token";
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

let _inMemoryToken: string | null = null;

function safeLocalStorageGet(key: string): string | null {
  try { return localStorage.getItem(key); } catch { return null; }
}

function safeLocalStorageSet(key: string, value: string): void {
  try { localStorage.setItem(key, value); } catch { /* fall back to in-memory */ }
}

export function getOrCreateToken(): string {
  const stored = safeLocalStorageGet(TOKEN_KEY);
  if (stored && UUID_V4.test(stored)) return stored;
  if (_inMemoryToken && UUID_V4.test(_inMemoryToken)) return _inMemoryToken;
  const token = crypto.randomUUID();
  _inMemoryToken = token;
  safeLocalStorageSet(TOKEN_KEY, token);
  return token;
}

export function getAuthHeaders(): { Authorization: string } {
  return { Authorization: `Bearer ${getOrCreateToken()}` };
}
