-- =====================================================================
--  SQUARES — onboarding + token ledger schema
--  Paste into Supabase Studio → SQL Editor → Run.
--  Safe to read top-to-bottom; every token movement is a ledger row and
--  every write goes through a SECURITY DEFINER function the client cannot
--  bypass. Clients can only READ their own data via RLS.
-- =====================================================================

create extension if not exists pgcrypto;   -- gen_random_uuid()

-- ---------------------------------------------------------------------
-- TABLES
-- ---------------------------------------------------------------------

-- One row per auth user (guests included). Mirrors auth.users.
create table if not exists public.profiles (
  id           uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default 'Player',
  is_guest     boolean not null default false,
  created_at   timestamptz not null default now()
);

-- A squares pool for one game.
create table if not exists public.pools (
  id              uuid primary key default gen_random_uuid(),
  away            text not null,
  home            text not null,
  price_per_square int  not null default 10,
  max_players     int  not null default 10,
  status          text not null default 'open',   -- open | live | final
  col_digits      int[],                           -- home digits, drawn at kickoff
  row_digits      int[],                           -- away digits, drawn at kickoff
  payout_split    int[] not null default '{15,25,15,45}',
  created_by      uuid references auth.users(id),
  created_at      timestamptz not null default now()
);

-- 100 squares per pool (idx 0..99 = row*10 + col).
create table if not exists public.squares (
  id         uuid primary key default gen_random_uuid(),
  pool_id    uuid not null references public.pools(id) on delete cascade,
  idx        int  not null check (idx between 0 and 99),
  owner_id   uuid references auth.users(id),
  claimed_at timestamptz,
  unique (pool_id, idx)
);

-- Append-only ledger. A user's balance is sum(delta) of their rows.
create table if not exists public.transactions (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users(id) on delete cascade,
  pool_id    uuid references public.pools(id) on delete set null,
  delta      int  not null,                        -- + credit, - debit
  reason     text not null,                        -- signup_grant | buy_in | refund | payout
  created_at timestamptz not null default now()
);
create index if not exists transactions_user_idx on public.transactions(user_id);

-- One settled result per quarter. The UNIQUE makes payouts idempotent.
create table if not exists public.results (
  id          uuid primary key default gen_random_uuid(),
  pool_id     uuid not null references public.pools(id) on delete cascade,
  quarter     int  not null check (quarter between 1 and 4),
  home_score  int  not null,
  away_score  int  not null,
  winning_idx int  not null,
  winner_id   uuid references auth.users(id),
  payout      int  not null default 0,
  created_at  timestamptz not null default now(),
  unique (pool_id, quarter)
);

-- ---------------------------------------------------------------------
-- ROW LEVEL SECURITY
--   Reads are scoped by these policies. WRITES to transactions/squares/
--   pools/results have NO user policy on purpose — they only happen
--   inside the SECURITY DEFINER functions below.
-- ---------------------------------------------------------------------

alter table public.profiles     enable row level security;
alter table public.pools        enable row level security;
alter table public.squares      enable row level security;
alter table public.transactions enable row level security;
alter table public.results      enable row level security;

-- profiles: you can see and edit only yourself
create policy "read own profile"   on public.profiles for select to authenticated using (auth.uid() = id);
create policy "update own profile" on public.profiles for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);

-- transactions: you can read only your own ledger; you can never write it
create policy "read own ledger" on public.transactions for select to authenticated using (auth.uid() = user_id);

-- pools / squares / results: any signed-in user can read (the lobby + board are shared)
create policy "read pools"   on public.pools   for select to authenticated using (true);
create policy "read squares" on public.squares for select to authenticated using (true);
create policy "read results" on public.results for select to authenticated using (true);

-- ---------------------------------------------------------------------
-- NEW USER → create profile + starting token grant
--   Fires once when an auth user is created (guest or full).
--   Guests get a smaller grant so clearing cookies can't farm tokens.
-- ---------------------------------------------------------------------

create or replace function public.handle_new_user()
returns trigger
language plpgsql security definer set search_path = public
as $$
declare
  v_guest boolean := coalesce(new.is_anonymous, false);
begin
  insert into public.profiles (id, display_name, is_guest)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'display_name', case when v_guest then 'Guest' else 'Player' end),
    v_guest
  )
  on conflict (id) do nothing;

  insert into public.transactions (user_id, delta, reason)
  values (new.id, case when v_guest then 500 else 1000 end, 'signup_grant');

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Keep profiles.is_guest in sync if a guest later links an email (upgrades).
create or replace function public.handle_user_upgrade()
returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  if old.is_anonymous is distinct from new.is_anonymous and new.is_anonymous = false then
    update public.profiles set is_guest = false where id = new.id;
  end if;
  return new;
end;
$$;

drop trigger if exists on_auth_user_upgraded on auth.users;
create trigger on_auth_user_upgraded
  after update on auth.users
  for each row execute function public.handle_user_upgrade();

-- ---------------------------------------------------------------------
-- BALANCE helper (reads only the caller's ledger)
-- ---------------------------------------------------------------------

create or replace function public.my_balance()
returns int
language sql stable security definer set search_path = public
as $$
  select coalesce(sum(delta), 0)::int
  from public.transactions
  where user_id = auth.uid();
$$;

-- ---------------------------------------------------------------------
-- CREATE POOL — inserts the pool + its 100 empty squares atomically
-- ---------------------------------------------------------------------

create or replace function public.create_pool(p_away text, p_home text, p_price int, p_max int)
returns public.pools
language plpgsql security definer set search_path = public
as $$
declare v_pool public.pools;
begin
  if auth.uid() is null then raise exception 'Not authenticated'; end if;

  insert into public.pools (away, home, price_per_square, max_players, created_by)
  values (p_away, p_home, greatest(p_price, 0), greatest(p_max, 1), auth.uid())
  returning * into v_pool;

  insert into public.squares (pool_id, idx)
  select v_pool.id, g from generate_series(0, 99) g;

  return v_pool;
end;
$$;

-- ---------------------------------------------------------------------
-- JOIN SQUARE — the buy-in. Verifies open / not-taken / under cap /
-- can afford, then claims + debits in one transaction. Row locks make
-- it race-safe if two people grab the same square at once.
-- ---------------------------------------------------------------------

create or replace function public.join_square(p_pool uuid, p_idx int)
returns public.squares
language plpgsql security definer set search_path = public
as $$
declare
  v_user    uuid := auth.uid();
  v_price   int;
  v_max     int;
  v_status  text;
  v_owned   int;
  v_balance int;
  v_square  public.squares;
begin
  if v_user is null then raise exception 'Not authenticated'; end if;

  select price_per_square, max_players, status
    into v_price, v_max, v_status
  from public.pools where id = p_pool for update;          -- lock pool
  if not found then raise exception 'Pool not found'; end if;
  if v_status <> 'open' then raise exception 'Pool is not open for joining'; end if;

  select * into v_square
  from public.squares where pool_id = p_pool and idx = p_idx for update;  -- lock square
  if not found then raise exception 'That square does not exist'; end if;
  if v_square.owner_id is not null then raise exception 'Square already taken'; end if;

  -- per-player cap = ceil(100 / max_players)  (matches the app's rule)
  select count(*) into v_owned
  from public.squares where pool_id = p_pool and owner_id = v_user;
  if v_owned >= ceil(100.0 / greatest(v_max, 1)) then
    raise exception 'You have reached your square limit for this pool';
  end if;

  -- balance check
  select coalesce(sum(delta), 0) into v_balance
  from public.transactions where user_id = v_user;
  if v_balance < v_price then raise exception 'Not enough tokens'; end if;

  update public.squares
    set owner_id = v_user, claimed_at = now()
  where id = v_square.id
  returning * into v_square;

  insert into public.transactions (user_id, pool_id, delta, reason)
  values (v_user, p_pool, -v_price, 'buy_in');

  return v_square;
end;
$$;

-- ---------------------------------------------------------------------
-- RELEASE SQUARE — give a square back while the pool is still open, refunds
-- ---------------------------------------------------------------------

create or replace function public.release_square(p_pool uuid, p_idx int)
returns public.squares
language plpgsql security definer set search_path = public
as $$
declare
  v_user uuid := auth.uid();
  v_price int; v_status text; v_square public.squares;
begin
  if v_user is null then raise exception 'Not authenticated'; end if;

  select price_per_square, status into v_price, v_status
  from public.pools where id = p_pool for update;
  if not found then raise exception 'Pool not found'; end if;
  if v_status <> 'open' then raise exception 'Pool is locked'; end if;

  select * into v_square
  from public.squares where pool_id = p_pool and idx = p_idx for update;
  if not found then raise exception 'That square does not exist'; end if;
  if v_square.owner_id is distinct from v_user then raise exception 'Not your square'; end if;

  update public.squares set owner_id = null, claimed_at = null
  where id = v_square.id returning * into v_square;

  insert into public.transactions (user_id, pool_id, delta, reason)
  values (v_user, p_pool, v_price, 'refund');

  return v_square;
end;
$$;

-- ---------------------------------------------------------------------
-- START POOL — host draws the numbers SERVER-SIDE (so the mapping is
-- trustworthy) and moves the pool to 'live'.
-- ---------------------------------------------------------------------

create or replace function public.start_pool(p_pool uuid)
returns public.pools
language plpgsql security definer set search_path = public
as $$
declare v_creator uuid; v_status text; v_pool public.pools;
begin
  select created_by, status into v_creator, v_status
  from public.pools where id = p_pool for update;
  if not found then raise exception 'Pool not found'; end if;
  if auth.uid() <> v_creator then raise exception 'Only the host can start the pool'; end if;
  if v_status <> 'open' then raise exception 'Pool already started'; end if;

  update public.pools set
    col_digits = (select array_agg(d order by random()) from unnest(array[0,1,2,3,4,5,6,7,8,9]) d),
    row_digits = (select array_agg(d order by random()) from unnest(array[0,1,2,3,4,5,6,7,8,9]) d),
    status     = 'live'
  where id = p_pool
  returning * into v_pool;

  return v_pool;
end;
$$;

-- ---------------------------------------------------------------------
-- PAY QUARTER — host settles a quarter. Finds the winning square from
-- the SERVER-stored digit draw, pays the owner. Idempotent: the UNIQUE
-- (pool, quarter) means a retry returns the existing result, never a
-- second payout.
-- ---------------------------------------------------------------------

create or replace function public.pay_quarter(p_pool uuid, p_quarter int, p_home int, p_away int)
returns public.results
language plpgsql security definer set search_path = public
as $$
declare
  v_creator uuid; v_status text; v_price int;
  v_col int[]; v_row int[]; v_split int[];
  v_ci int; v_ri int; v_idx int;
  v_winner uuid; v_sold int; v_pot int; v_payout int;
  v_result public.results;
begin
  if p_quarter < 1 or p_quarter > 4 then raise exception 'Invalid quarter'; end if;

  select created_by, status, price_per_square, col_digits, row_digits, payout_split
    into v_creator, v_status, v_price, v_col, v_row, v_split
  from public.pools where id = p_pool for update;
  if not found then raise exception 'Pool not found'; end if;
  if auth.uid() <> v_creator then raise exception 'Only the host can settle quarters'; end if;
  if v_status <> 'live' then raise exception 'Pool is not live'; end if;
  if v_col is null or v_row is null then raise exception 'Numbers have not been drawn'; end if;

  -- already settled? return it, do not pay twice
  select * into v_result from public.results where pool_id = p_pool and quarter = p_quarter;
  if found then return v_result; end if;

  -- winning square from the stored draw (pg arrays are 1-based)
  v_ci := array_position(v_col, p_home % 10) - 1;
  v_ri := array_position(v_row, p_away % 10) - 1;
  v_idx := v_ri * 10 + v_ci;

  select owner_id into v_winner from public.squares where pool_id = p_pool and idx = v_idx;

  select count(*) into v_sold from public.squares where pool_id = p_pool and owner_id is not null;
  v_pot := v_sold * v_price;
  v_payout := floor(v_pot * v_split[p_quarter] / 100.0);

  insert into public.results (pool_id, quarter, home_score, away_score, winning_idx, winner_id, payout)
  values (p_pool, p_quarter, p_home, p_away, v_idx, v_winner, v_payout)
  returning * into v_result;

  if v_winner is not null and v_payout > 0 then
    insert into public.transactions (user_id, pool_id, delta, reason)
    values (v_winner, p_pool, v_payout, 'payout');
  end if;

  if p_quarter = 4 then
    update public.pools set status = 'final' where id = p_pool;
  end if;

  return v_result;
end;
$$;

-- ---------------------------------------------------------------------
-- GRANTS — let signed-in users call the functions (RLS still applies
-- to the tables those functions touch when read back).
-- ---------------------------------------------------------------------

grant execute on function public.my_balance()                              to authenticated;
grant execute on function public.create_pool(text, text, int, int)         to authenticated;
grant execute on function public.join_square(uuid, int)                    to authenticated;
grant execute on function public.release_square(uuid, int)                 to authenticated;
grant execute on function public.start_pool(uuid)                          to authenticated;
grant execute on function public.pay_quarter(uuid, int, int, int)          to authenticated;

-- ---------------------------------------------------------------------
-- REALTIME — let the client live-update the balance and the board.
-- ---------------------------------------------------------------------

alter publication supabase_realtime add table public.transactions;
alter publication supabase_realtime add table public.squares;
alter publication supabase_realtime add table public.results;

-- Done. Next: enable Anonymous sign-ins in Authentication settings, then
-- run the front-end demo.
