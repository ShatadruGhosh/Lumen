create table if not exists public.lumen_audit_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users (id) on delete set null,
  user_email text,
  tool_name text not null,
  priority text not null default 'NORMAL',
  arguments jsonb,
  result jsonb,
  decision text,
  latency_us double precision,
  mode text not null default 'live',
  created_at timestamptz not null default now()
);

alter table public.lumen_audit_logs enable row level security;
revoke all on table public.lumen_audit_logs from anon;
grant select, insert on table public.lumen_audit_logs to authenticated;

drop policy if exists "Users can view their own audit logs" on public.lumen_audit_logs;
create policy "Users can view their own audit logs"
  on public.lumen_audit_logs for select to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "Users can insert their own audit logs" on public.lumen_audit_logs;
create policy "Users can insert their own audit logs"
  on public.lumen_audit_logs for insert to authenticated
  with check ((select auth.uid()) = user_id);
