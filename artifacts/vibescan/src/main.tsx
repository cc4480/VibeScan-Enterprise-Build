import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import { setAuthTokenGetter } from "@workspace/api-client-react";

const TOKEN_KEY = "vibescan_client_token";

function getOrCreateToken(): string {
  let token = localStorage.getItem(TOKEN_KEY);
  if (!token || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(token)) {
    token = crypto.randomUUID();
    localStorage.setItem(TOKEN_KEY, token);
  }
  return token;
}

setAuthTokenGetter(getOrCreateToken);

createRoot(document.getElementById("root")!).render(<App />);
