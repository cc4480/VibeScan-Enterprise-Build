import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import { setAuthTokenGetter } from "@workspace/api-client-react";

const TOKEN_KEY = "vibescan_client_token";
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Fallback in-memory token when localStorage is unavailable (e.g. cross-origin
// iframe with strict privacy settings — a SecurityError would otherwise crash
// the entire React app before anything renders).
let _inMemoryToken: string | null = null;

function safeLocalStorageGet(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function safeLocalStorageSet(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // ignore — we fall back to in-memory token
  }
}

function getOrCreateToken(): string {
  // Try persistent storage first
  const stored = safeLocalStorageGet(TOKEN_KEY);
  if (stored && UUID_V4.test(stored)) return stored;

  // Use or create an in-memory token as fallback
  if (_inMemoryToken && UUID_V4.test(_inMemoryToken)) return _inMemoryToken;

  const token = crypto.randomUUID();
  _inMemoryToken = token;
  safeLocalStorageSet(TOKEN_KEY, token);
  return token;
}

setAuthTokenGetter(getOrCreateToken);

createRoot(document.getElementById("root")!).render(<App />);
