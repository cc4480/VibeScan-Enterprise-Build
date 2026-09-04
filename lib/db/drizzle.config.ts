import { defineConfig } from "drizzle-kit";
import path from "path";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL, ensure the database is provisioned");
}

export default defineConfig({
  schema: path.join(__dirname, "./src/schema/index.ts").split(path.sep).join("/"),
  // Generated SQL is committed and reviewed like any other code. `push` infers
  // a diff against whatever is live and applies it unreviewed, which is fine on
  // a laptop and unacceptable against production data.
  // Relative, not absolute: drizzle-kit resolves this against the working
  // directory when reading back the snapshot, so an absolute value gets joined
  // onto the cwd and produces a doubled path on the second generate.
  out: "./migrations",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL,
  },
});
