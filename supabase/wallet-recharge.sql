-- MIRDDA TELICOM: manual wallet recharge requests
create table if not exists public.wallet_recharge_requests (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.profiles(id) on delete cascade,
  amount numeric(12,2) not null check (amount between 1 and 100000),
  note text,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  admin_note text,
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists wallet_recharge_customer_created_idx
on public.wallet_recharge_requests(customer_id,created_at desc);
alter table public.wallet_recharge_requests enable row level security;
drop policy if exists "retailer read own recharge requests or admin" on public.wallet_recharge_requests;
create policy "retailer read own recharge requests or admin"
on public.wallet_recharge_requests for select to authenticated
using (customer_id=auth.uid() or public.is_admin());

create or replace function public.request_wallet_recharge(p_amount numeric,p_note text default null)
returns uuid language plpgsql security definer set search_path=public
as $$
declare v_id uuid;
begin
 if auth.uid() is null then raise exception 'Please sign in'; end if;
 if p_amount is null or p_amount<1 or p_amount>100000 then raise exception 'Amount must be between 1 and 100000'; end if;
 insert into public.wallet_recharge_requests(customer_id,amount,note)
 values(auth.uid(),round(p_amount,2),left(coalesce(p_note,''),250))
 returning id into v_id;
 return v_id;
end;
$$;

create or replace function public.admin_review_wallet_recharge(p_request_id uuid,p_status text,p_admin_note text default null)
returns void language plpgsql security definer set search_path=public
as $$
declare v_req public.wallet_recharge_requests%rowtype;
begin
 if not public.is_admin() then raise exception 'Admin access required'; end if;
 if p_status not in ('approved','rejected') then raise exception 'Invalid status'; end if;
 select * into v_req from public.wallet_recharge_requests where id=p_request_id for update;
 if not found then raise exception 'Request not found'; end if;
 if v_req.status<>'pending' then raise exception 'This request has already been reviewed'; end if;
 update public.wallet_recharge_requests
 set status=p_status,admin_note=left(coalesce(p_admin_note,''),250),reviewed_at=now()
 where id=p_request_id;
 if p_status='approved' then
   update public.profiles set wallet_balance=wallet_balance+v_req.amount where id=v_req.customer_id;
   insert into public.wallet_transactions(customer_id,amount,type,description,reference)
   values(v_req.customer_id,v_req.amount,'credit','Wallet recharge approved',v_req.id::text);
 end if;
end;
$$;
revoke all on function public.request_wallet_recharge(numeric,text) from public,anon;
grant execute on function public.request_wallet_recharge(numeric,text) to authenticated;
revoke all on function public.admin_review_wallet_recharge(uuid,text,text) from public,anon;
grant execute on function public.admin_review_wallet_recharge(uuid,text,text) to authenticated;
