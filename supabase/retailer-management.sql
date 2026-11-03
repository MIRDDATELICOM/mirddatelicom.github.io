-- Retailer management: preserve order and wallet history while allowing admin block/unblock.
alter table public.profiles
add column if not exists active boolean not null default true;

-- Existing retailer accounts remain active by default.
update public.profiles set active = true where active is null;
