-- MIRDDA TELICOM Retailer Portal: Supabase starter schema
-- Run this entire file in Supabase SQL Editor after creating a project.
-- Keep the Storage bucket private. Never put a service_role key in browser code.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  retailer_id text unique not null,
  full_name text,
  phone text,
  role text not null default 'retailer' check (role in ('retailer','admin')),
  wallet_balance numeric(12,2) not null default 0 check (wallet_balance >= 0),
  created_at timestamptz not null default now()
);

create table if not exists public.services (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  price numeric(12,2) not null check (price >= 0),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.profiles(id),
  service_id uuid not null references public.services(id),
  amount numeric(12,2) not null check (amount >= 0),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  pdf_path text,
  admin_note text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wallet_transactions (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.profiles(id),
  order_id uuid references public.orders(id),
  amount numeric(12,2) not null check (amount > 0),
  type text not null check (type in ('credit','debit','refund')),
  description text not null,
  reference text,
  created_at timestamptz not null default now()
);

create table if not exists public.payment_topups (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.profiles(id),
  amount numeric(12,2) not null check (amount > 0),
  gateway text,
  gateway_payment_id text unique,
  status text not null default 'initiated' check (status in ('initiated','paid','failed','credited')),
  created_at timestamptz not null default now()
);

create index if not exists orders_customer_created_idx on public.orders(customer_id, created_at desc);
create index if not exists orders_status_created_idx on public.orders(status, created_at desc);
create index if not exists wallet_customer_created_idx on public.wallet_transactions(customer_id, created_at desc);

create or replace function public.make_retailer_profile()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles(id, retailer_id, full_name)
  values (new.id, 'MT' || upper(substr(replace(new.id::text,'-',''),1,8)), coalesce(new.raw_user_meta_data->>'full_name',''));
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_retailer on auth.users;
create trigger on_auth_user_created_retailer
after insert on auth.users
for each row execute procedure public.make_retailer_profile();

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public
as $$
  select exists(select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

-- Place an order and debit the wallet atomically. Client cannot choose the price.
create or replace function public.place_order(p_service_id uuid)
returns uuid language plpgsql security definer set search_path = public
as $$
declare
  v_price numeric(12,2);
  v_order_id uuid;
begin
  if auth.uid() is null then raise exception 'Please sign in'; end if;
  select price into v_price from public.services where id = p_service_id and active = true;
  if v_price is null then raise exception 'Service is unavailable'; end if;

  update public.profiles
    set wallet_balance = wallet_balance - v_price
    where id = auth.uid() and wallet_balance >= v_price;
  if not found then raise exception 'Insufficient wallet balance'; end if;

  insert into public.orders(customer_id, service_id, amount, status)
    values(auth.uid(), p_service_id, v_price, 'pending')
    returning id into v_order_id;

  insert into public.wallet_transactions(customer_id, order_id, amount, type, description)
    values(auth.uid(), v_order_id, v_price, 'debit', 'Order payment');
  return v_order_id;
end;
$$;

-- Admin-only order decision. Refund a rejected order exactly once.
create or replace function public.admin_set_order_status(p_order_id uuid, p_status text, p_pdf_path text default null, p_note text default null)
returns void language plpgsql security definer set search_path = public
as $$
declare
  v_order public.orders%rowtype;
begin
  if not public.is_admin() then raise exception 'Admin access required'; end if;
  if p_status not in ('approved','rejected') then raise exception 'Invalid status'; end if;
  select * into v_order from public.orders where id = p_order_id for update;
  if not found then raise exception 'Order not found'; end if;
  if v_order.status <> 'pending' then raise exception 'Only pending orders can be processed'; end if;
  if p_status = 'approved' and (p_pdf_path is null or length(p_pdf_path)=0) then
    raise exception 'PDF is required for approval';
  end if;

  update public.orders
    set status = p_status, pdf_path = case when p_status='approved' then p_pdf_path else null end,
        admin_note = p_note, updated_at = now()
    where id = p_order_id;

  if p_status = 'rejected' then
    update public.profiles set wallet_balance = wallet_balance + v_order.amount where id = v_order.customer_id;
    insert into public.wallet_transactions(customer_id, order_id, amount, type, description)
      values(v_order.customer_id, v_order.id, v_order.amount, 'refund', 'Order rejected — automatic refund');
  end if;
end;
$$;

alter table public.profiles enable row level security;
alter table public.services enable row level security;
alter table public.orders enable row level security;
alter table public.wallet_transactions enable row level security;
alter table public.payment_topups enable row level security;

drop policy if exists "profile read own or admin" on public.profiles;
create policy "profile read own or admin" on public.profiles for select to authenticated
using (id = auth.uid() or public.is_admin());
drop policy if exists "admin manage profiles" on public.profiles;
create policy "admin manage profiles" on public.profiles for update to authenticated
using (public.is_admin()) with check (public.is_admin());

drop policy if exists "authenticated read active services" on public.services;
create policy "authenticated read active services" on public.services for select to authenticated
using (active = true or public.is_admin());
drop policy if exists "admin manage services" on public.services;
create policy "admin manage services" on public.services for all to authenticated
using (public.is_admin()) with check (public.is_admin());

drop policy if exists "customer read own orders or admin" on public.orders;
create policy "customer read own orders or admin" on public.orders for select to authenticated
using (customer_id = auth.uid() or public.is_admin());

drop policy if exists "customer read own wallet ledger or admin" on public.wallet_transactions;
create policy "customer read own wallet ledger or admin" on public.wallet_transactions for select to authenticated
using (customer_id = auth.uid() or public.is_admin());

drop policy if exists "customer read own topups or admin" on public.payment_topups;
create policy "customer read own topups or admin" on public.payment_topups for select to authenticated
using (customer_id = auth.uid() or public.is_admin());

-- Private bucket: uploaded PDFs are never publicly accessible.
insert into storage.buckets(id, name, public, file_size_limit, allowed_mime_types)
values ('retailer-pdfs','retailer-pdfs',false,10485760,array['application/pdf'])
on conflict (id) do update set public=false, file_size_limit=10485760, allowed_mime_types=array['application/pdf'];

drop policy if exists "admin upload retailer PDFs" on storage.objects;
create policy "admin upload retailer PDFs" on storage.objects for insert to authenticated
with check (bucket_id = 'retailer-pdfs' and public.is_admin());
drop policy if exists "admin read retailer PDFs" on storage.objects;
create policy "admin read retailer PDFs" on storage.objects for select to authenticated
using (bucket_id = 'retailer-pdfs' and public.is_admin());
drop policy if exists "admin update retailer PDFs" on storage.objects;
create policy "admin update retailer PDFs" on storage.objects for update to authenticated
using (bucket_id = 'retailer-pdfs' and public.is_admin())
with check (bucket_id = 'retailer-pdfs' and public.is_admin());
drop policy if exists "admin delete retailer PDFs" on storage.objects;
create policy "admin delete retailer PDFs" on storage.objects for delete to authenticated
using (bucket_id = 'retailer-pdfs' and public.is_admin());

-- After creating your own account, promote that account to admin in SQL Editor:
-- update public.profiles set role='admin' where id='YOUR_AUTH_USER_UUID';
