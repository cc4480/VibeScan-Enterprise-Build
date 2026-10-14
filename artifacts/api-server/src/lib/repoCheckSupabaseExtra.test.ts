import { describe, it, expect } from "vitest";
import { supabaseExtraFindings, supabaseAuthConfigFindings } from "./repoCheckSupabaseExtra";
import type { RepoFile, RepoRef } from "./repoFinding";

const ref: RepoRef = { owner: "acme", repo: "app" };
const sql = (content: string, path = "supabase/migrations/20260101000000_init.sql"): RepoFile[] => [{ path, content }];
const names = (content: string) => supabaseExtraFindings(sql(content), ref).map((v) => v.name);

describe("user_metadata in access decisions", () => {
  it("flags a policy that trusts user_metadata, and a function that does", () => {
    const policy = `create policy "admins" on public.orders for all to authenticated using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');`;
    expect(names(policy)).toEqual(["Supabase Access Decided From user_metadata"]);
    const fn = `create function public.is_admin() returns boolean language sql as $$ select (auth.jwt() -> 'user_metadata' ->> 'role') = 'admin' $$;`;
    expect(names(fn)).toEqual(["Supabase Access Decided From user_metadata"]);
    expect(names(`create policy "x" on public.t using (exists (select 1 from auth.users u where u.id = auth.uid() and u.raw_user_meta_data->>'role' = 'admin'));`)).toEqual(["Supabase Access Decided From user_metadata"]);
  });

  it("clean twin: app_metadata, or a roles table", () => {
    expect(names(`create policy "admins" on public.orders for all to authenticated using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');`)).toEqual([]);
    expect(names(`create policy "own" on public.orders for select to authenticated using (user_id = (select auth.uid()));`)).toEqual([]);
    // A commented-out line is not a policy.
    expect(names(`-- create policy "a" on public.t using (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin');`)).toEqual([]);
  });
});

describe("SECURITY DEFINER functions callable through the API", () => {
  const definer = `create or replace function public.delete_account(target uuid) returns void language plpgsql security definer set search_path = '' as $$ begin delete from public.profiles where id = target; end $$;`;

  it("flags one with no caller check and no revoke", () => {
    const found = supabaseExtraFindings(sql(definer), ref);
    expect(found.map((v) => v.name)).toEqual(["Supabase SECURITY DEFINER Function Callable by Anyone"]);
    expect(found[0]!.confidence).toBeLessThan(65);
  });

  it("clean twin: revoked from anon, checks the caller, is a trigger function, or runs as the invoker", () => {
    expect(names(`${definer}\nrevoke execute on function public.delete_account(uuid) from public, anon;`)).toEqual([]);
    expect(names(`create function public.delete_me() returns void language plpgsql security definer as $$ begin if auth.uid() is null then raise exception 'no'; end if; delete from public.profiles where id = auth.uid(); end $$;`)).toEqual([]);
    expect(names(`create function public.handle_new_user() returns trigger language plpgsql security definer as $$ begin insert into public.profiles(id) values (new.id); return new; end $$;`)).toEqual([]);
    expect(names(`create function public.list_items() returns setof items language sql security invoker as $$ select * from items $$;`)).toEqual([]);
    expect(names(`${definer}\nalter default privileges in schema public revoke execute on functions from public, anon;`)).toEqual([]);
  });
});

describe("sensitive columns and public buckets", () => {
  it("flags a password column and a sensitive-looking bucket made public", () => {
    expect(names(`create table public.members (\n  id uuid primary key,\n  email text,\n  password text not null\n);`)).toEqual(["Supabase Table Holds a Sensitive-Looking Column"]);
    expect(names(`insert into storage.buckets (id, name, public) values ('invoices', 'invoices', true);`)).toEqual(["Supabase Storage Bucket Named Like Private Files Is Public"]);
    expect(names(`update storage.buckets set public = true where id = 'customer-documents';`)).toEqual(["Supabase Storage Bucket Named Like Private Files Is Public"]);
  });

  it("clean twin: a hashed column, a public avatars bucket, a private invoices bucket", () => {
    expect(names(`create table public.members (\n  id uuid primary key,\n  password_hash text\n);`)).toEqual([]);
    expect(names(`insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);`)).toEqual([]);
    expect(names(`insert into storage.buckets (id, name, public) values ('invoices', 'invoices', false);`)).toEqual([]);
  });

  it("reads nothing when the repository has no migrations", () => {
    expect(supabaseExtraFindings([{ path: "src/app.ts", content: "create table x (password text)" }], ref)).toEqual([]);
  });
});

describe("supabase/config.toml", () => {
  const cfg = (body: string): RepoFile => ({ path: "supabase/config.toml", content: body });

  it("flags anonymous sign-ins and unconfirmed email sign-ups", () => {
    expect(supabaseAuthConfigFindings(cfg(`[auth]\nenable_anonymous_sign_ins = true\n`), ref).map((v) => v.name)).toEqual(["Supabase Anonymous Sign-Ins Are Enabled"]);
    expect(supabaseAuthConfigFindings(cfg(`[auth.email]\nenable_signup = true\nenable_confirmations = false\n`), ref).map((v) => v.name)).toEqual(["Supabase Email Sign-Ups Are Not Confirmed"]);
  });

  it("clean twin: both off, and a commented-out setting", () => {
    expect(supabaseAuthConfigFindings(cfg(`[auth]\nenable_anonymous_sign_ins = false\n[auth.email]\nenable_confirmations = true\n# enable_anonymous_sign_ins = true\n`), ref)).toEqual([]);
  });
});
