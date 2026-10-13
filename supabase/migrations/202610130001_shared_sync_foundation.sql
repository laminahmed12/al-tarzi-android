-- Al-Tarzi shared-device synchronization foundation.
-- Draft migration: review and apply only to a dedicated Al-Tarzi Supabase project.
-- Does not alter the existing local app or the build-34 reference.

create extension if not exists pgcrypto;

create table if not exists public.tarzi_shops (
  id uuid primary key default gen_random_uuid(),
  name text not null default 'التارزي',
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now()
);

create table if not exists public.tarzi_shop_members (
  shop_id uuid not null references public.tarzi_shops(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner', 'worker', 'viewer')),
  created_at timestamptz not null default now(),
  primary key (shop_id, user_id)
);

-- A record-level envelope allows customer/order fields to evolve without destructive
-- schema rewrites. record_id must be stable across devices; payload is validated by
-- the application before upload.
create table if not exists public.tarzi_sync_records (
  shop_id uuid not null references public.tarzi_shops(id) on delete cascade,
  record_type text not null check (record_type in ('customer', 'order', 'settings')),
  record_id text not null,
  payload jsonb not null,
  revision bigint not null default 1 check (revision > 0),
  updated_by uuid not null references auth.users(id) on delete restrict,
  updated_at timestamptz not null default now(),
  deleted_at timestamptz,
  primary key (shop_id, record_type, record_id)
);

create index if not exists tarzi_sync_records_shop_updated_idx
  on public.tarzi_sync_records (shop_id, updated_at);

create table if not exists public.tarzi_device_invites (
  id uuid primary key default gen_random_uuid(),
  shop_id uuid not null references public.tarzi_shops(id) on delete cascade,
  token_hash text not null unique,
  role text not null check (role in ('worker', 'viewer')),
  expires_at timestamptz not null,
  max_uses integer not null default 1 check (max_uses between 1 and 20),
  uses integer not null default 0 check (uses >= 0 and uses <= max_uses),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now()
);

create or replace function public.tarzi_is_member(p_shop_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.tarzi_shop_members m
    where m.shop_id = p_shop_id and m.user_id = auth.uid()
  );
$$;

create or replace function public.tarzi_is_owner(p_shop_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.tarzi_shop_members m
    where m.shop_id = p_shop_id
      and m.user_id = auth.uid()
      and m.role = 'owner'
  );
$$;

revoke all on function public.tarzi_is_member(uuid) from public;
revoke all on function public.tarzi_is_owner(uuid) from public;
grant execute on function public.tarzi_is_member(uuid) to authenticated;
grant execute on function public.tarzi_is_owner(uuid) to authenticated;

alter table public.tarzi_shops enable row level security;
alter table public.tarzi_shop_members enable row level security;
alter table public.tarzi_sync_records enable row level security;
alter table public.tarzi_device_invites enable row level security;

drop policy if exists "tarzi members can view their shops" on public.tarzi_shops;
create policy "tarzi members can view their shops"
on public.tarzi_shops for select to authenticated
using (public.tarzi_is_member(id));

drop policy if exists "owners can update their shop" on public.tarzi_shops;
create policy "owners can update their shop"
on public.tarzi_shops for update to authenticated
using (public.tarzi_is_owner(id))
with check (public.tarzi_is_owner(id));

drop policy if exists "members can view membership list" on public.tarzi_shop_members;
create policy "members can view membership list"
on public.tarzi_shop_members for select to authenticated
using (public.tarzi_is_member(shop_id));

drop policy if exists "owners can add or change members" on public.tarzi_shop_members;
create policy "owners can add or change members"
on public.tarzi_shop_members for insert to authenticated
with check (public.tarzi_is_owner(shop_id));

drop policy if exists "owners can remove members" on public.tarzi_shop_members;
create policy "owners can remove members"
on public.tarzi_shop_members for delete to authenticated
using (public.tarzi_is_owner(shop_id) and user_id <> auth.uid());

drop policy if exists "members can read shared records" on public.tarzi_sync_records;
create policy "members can read shared records"
on public.tarzi_sync_records for select to authenticated
using (public.tarzi_is_member(shop_id));

drop policy if exists "owners and workers can create records" on public.tarzi_sync_records;
create policy "owners and workers can create records"
on public.tarzi_sync_records for insert to authenticated
with check (
  public.tarzi_is_member(shop_id)
  and updated_by = auth.uid()
  and exists (
    select 1 from public.tarzi_shop_members m
    where m.shop_id = public.tarzi_sync_records.shop_id and m.user_id = auth.uid()
      and m.role in ('owner', 'worker')
  )
);

drop policy if exists "owners and workers can update records" on public.tarzi_sync_records;
create policy "owners and workers can update records"
on public.tarzi_sync_records for update to authenticated
using (
  public.tarzi_is_member(shop_id)
  and exists (
    select 1 from public.tarzi_shop_members m
    where m.shop_id = public.tarzi_sync_records.shop_id and m.user_id = auth.uid()
      and m.role in ('owner', 'worker')
  )
)
with check (
  public.tarzi_is_member(shop_id)
  and updated_by = auth.uid()
  and exists (
    select 1 from public.tarzi_shop_members m
    where m.shop_id = public.tarzi_sync_records.shop_id and m.user_id = auth.uid()
      and m.role in ('owner', 'worker')
  )
);

drop policy if exists "owners can manage device invites" on public.tarzi_device_invites;
create policy "owners can manage device invites"
on public.tarzi_device_invites for all to authenticated
using (public.tarzi_is_owner(shop_id))
with check (public.tarzi_is_owner(shop_id));

-- Intentionally no public/anon policies. Shop creation, first-owner membership,
-- invite redemption, and atomic revision/conflict resolution must be implemented
-- through reviewed server-side RPCs before client sync is enabled.
