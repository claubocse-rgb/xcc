-- XCC app schema for Supabase. Run once in the SQL editor.
-- Admin email (auto-approved, admin role):
--   clau.bocse@gmail.com

create extension if not exists pgcrypto;

-- ---------- tables ----------
create table if not exists public.teams (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 40),
  created_at timestamptz not null default now()
);

create table if not exists public.cars (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null,
  label text not null default '' check (char_length(label) <= 40),
  seats int not null default 3 check (seats between 0 and 8),
  from_city text not null default '' check (char_length(from_city) <= 40),
  when_text text not null default '' check (char_length(when_text) <= 40),
  note text not null default '' check (char_length(note) <= 80),
  created_at timestamptz not null default now()
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null default '' check (char_length(name) <= 30),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  role text not null default 'member' check (role in ('member','admin')),
  team uuid references public.teams(id) on delete set null,
  ride uuid references public.cars(id) on delete set null,
  items jsonb not null default '{}'::jsonb,
  own_transport boolean not null default false,
  created_at timestamptz not null default now()
);

alter table public.cars drop constraint if exists cars_owner_fkey;
alter table public.cars add constraint cars_owner_fkey foreign key (owner) references public.profiles(id) on delete cascade;

create table if not exists public.items (
  id text primary key,
  name text not null check (char_length(name) between 1 and 60),
  cat text not null default 'Altele' check (char_length(cat) <= 30),
  ord numeric not null default 0
);

create table if not exists public.config (
  id int primary key default 1 check (id = 1),
  start_date date,
  hero_url text not null default ''
);
insert into public.config (id) values (1) on conflict do nothing;

-- ---------- helpers ----------
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin' and status = 'approved');
$$;

create or replace function public.is_approved() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and status = 'approved');
$$;

-- new account -> pending profile (the organiser is approved admin)
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, name, status, role)
  values (
    new.id,
    left(coalesce(nullif(trim(new.raw_user_meta_data->>'name'), ''), split_part(new.email, '@', 1)), 30),
    case when lower(new.email) = 'clau.bocse@gmail.com' then 'approved' else 'pending' end,
    case when lower(new.email) = 'clau.bocse@gmail.com' then 'admin' else 'member' end
  ) on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- members may not change their own status / role / team; rides respect car capacity
create or replace function public.guard_profile() returns trigger
language plpgsql security definer set search_path = public as $$
declare cap int; used int; car_owner uuid;
begin
  if not public.is_admin() then
    if new.status is distinct from old.status or new.role is distinct from old.role or new.team is distinct from old.team then
      raise exception 'Doar organizatorul poate schimba statusul, rolul sau echipa.';
    end if;
  end if;
  if new.ride is not null and new.ride is distinct from old.ride then
    select seats, owner into cap, car_owner from public.cars where id = new.ride;
    if car_owner is distinct from new.id then
      select count(*) into used from public.profiles p, public.cars c
        where p.ride = new.ride and c.id = new.ride and p.id <> c.owner and p.id <> new.id;
      if used >= cap then raise exception 'Mașina e plină.'; end if;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists guard_profile on public.profiles;
create trigger guard_profile before update on public.profiles
  for each row execute function public.guard_profile();

-- set one checklist entry on your own profile without overwriting the rest
create or replace function public.set_item(item_id text, val jsonb) returns void
language sql security invoker set search_path = public as $$
  update public.profiles set items = jsonb_set(coalesce(items, '{}'::jsonb), array[item_id], val, true)
  where id = auth.uid();
$$;

-- ---------- row level security ----------
alter table public.profiles enable row level security;
alter table public.items enable row level security;
alter table public.teams enable row level security;
alter table public.cars enable row level security;
alter table public.config enable row level security;

drop policy if exists "profiles read" on public.profiles;
create policy "profiles read" on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_admin() or (public.is_approved() and status = 'approved'));
drop policy if exists "profiles update own" on public.profiles;
create policy "profiles update own" on public.profiles for update to authenticated
  using (id = auth.uid() and public.is_approved()) with check (id = auth.uid());
drop policy if exists "profiles name while pending" on public.profiles;
create policy "profiles name while pending" on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());
drop policy if exists "profiles admin" on public.profiles;
create policy "profiles admin" on public.profiles for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists "items read" on public.items;
create policy "items read" on public.items for select to authenticated using (public.is_approved());
drop policy if exists "items admin" on public.items;
create policy "items admin" on public.items for all to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists "teams read" on public.teams;
create policy "teams read" on public.teams for select to authenticated using (public.is_approved());
drop policy if exists "teams admin" on public.teams;
create policy "teams admin" on public.teams for all to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists "cars read" on public.cars;
create policy "cars read" on public.cars for select to authenticated using (public.is_approved());
drop policy if exists "cars insert own" on public.cars;
create policy "cars insert own" on public.cars for insert to authenticated
  with check (owner = auth.uid() and public.is_approved());
drop policy if exists "cars change own" on public.cars;
create policy "cars change own" on public.cars for update to authenticated
  using (owner = auth.uid() or public.is_admin()) with check (owner = auth.uid() or public.is_admin());
drop policy if exists "cars delete own" on public.cars;
create policy "cars delete own" on public.cars for delete to authenticated
  using (owner = auth.uid() or public.is_admin());

drop policy if exists "config read" on public.config;
create policy "config read" on public.config for select to anon, authenticated using (true);
drop policy if exists "config admin" on public.config;
create policy "config admin" on public.config for update to authenticated using (public.is_admin()) with check (public.is_admin());

-- ---------- photo storage (home page picture) ----------
insert into storage.buckets (id, name, public) values ('media', 'media', true) on conflict (id) do nothing;
drop policy if exists "media admin insert" on storage.objects;
create policy "media admin insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'media' and public.is_admin());
drop policy if exists "media admin update" on storage.objects;
create policy "media admin update" on storage.objects for update to authenticated
  using (bucket_id = 'media' and public.is_admin());
drop policy if exists "media admin delete" on storage.objects;
create policy "media admin delete" on storage.objects for delete to authenticated
  using (bucket_id = 'media' and public.is_admin());

-- ---------- live updates ----------
do $$ begin
  begin alter publication supabase_realtime add table public.profiles; exception when others then null; end;
  begin alter publication supabase_realtime add table public.items; exception when others then null; end;
  begin alter publication supabase_realtime add table public.teams; exception when others then null; end;
  begin alter publication supabase_realtime add table public.cars; exception when others then null; end;
  begin alter publication supabase_realtime add table public.config; exception when others then null; end;
end $$;

-- ---------- equipment list (official 4M XCC list) ----------
insert into public.items (id, name, cat, ord) values
  ('p01', 'Rucsac de tură (min. 50 L)', 'Personal obligatoriu', 1),
  ('p02', 'Frontală + baterii de rezervă sau power bank', 'Personal obligatoriu', 2),
  ('p03', 'Produse de igienă (strictul necesar)', 'Personal obligatoriu', 3),
  ('p04', 'Biblie', 'Personal obligatoriu', 4),
  ('p05', 'Folie de supraviețuire / sac de urgență', 'Personal obligatoriu', 5),
  ('p06', 'Lopățică pentru nevoi', 'Personal obligatoriu', 6),
  ('p07', 'Cremă cu protecție UV', 'Personal obligatoriu', 7),
  ('e01', 'Corturi', 'Echipă obligatoriu', 10),
  ('e02', 'Busolă (min. 1/echipă)', 'Echipă obligatoriu', 11),
  ('e03', 'Brichetă (min. 1/echipă)', 'Echipă obligatoriu', 12),
  ('e04', 'Fierăstrău de mână (1/echipă)', 'Echipă obligatoriu', 13),
  ('e05', 'Arzător + butelii (2–3/echipă)', 'Echipă obligatoriu', 14),
  ('h01', 'Geacă impermeabilă', 'Îmbrăcăminte obligatoriu', 20),
  ('h01b', 'Pantaloni impermeabili', 'Îmbrăcăminte obligatoriu', 20.5),
  ('h02', 'Bocanci de tură', 'Îmbrăcăminte obligatoriu', 21),
  ('h03', 'Polar cu mânecă lungă', 'Îmbrăcăminte obligatoriu', 22),
  ('h04', 'Strat de bază (bluză + pantaloni)', 'Îmbrăcăminte obligatoriu', 23),
  ('h05', 'Mai multe seturi de lenjerie', 'Îmbrăcăminte obligatoriu', 24),
  ('h06', 'Buff sau căciulă', 'Îmbrăcăminte obligatoriu', 25),
  ('h07', 'Mănuși', 'Îmbrăcăminte obligatoriu', 26),
  ('h08', 'Șosete groase', 'Îmbrăcăminte obligatoriu', 27),
  ('h09', 'Pantaloni scurți + tricou (pentru ud/murdar)', 'Îmbrăcăminte obligatoriu', 28),
  ('h10', 'Adidași (pentru ud/murdar)', 'Îmbrăcăminte obligatoriu', 29),
  ('s01', 'Sac de dormit călduros (în husă)', 'Dormit obligatoriu', 30),
  ('s02', 'Izopren sau saltea', 'Dormit obligatoriu', 31),
  ('m01', 'Tacâmuri', 'Masă obligatoriu', 40),
  ('m02', 'Oală 0,5–1 L', 'Masă obligatoriu', 41),
  ('m03', 'Cană', 'Masă obligatoriu', 42),
  ('m04', '2 L de apă', 'Masă obligatoriu', 43),
  ('m05', 'Prosop', 'Masă obligatoriu', 44),
  ('o01', 'Ochelari de soare', 'Opțional', 50),
  ('o02', 'Pelerină impermeabilă', 'Opțional', 51),
  ('o03', 'Husă de ploaie pentru rucsac', 'Opțional', 52),
  ('o04', 'Bețe de trekking', 'Opțional', 53),
  ('o05', 'Briceag / cuțit multifuncțional', 'Opțional', 54),
  ('o06', 'Pernă', 'Opțional', 55),
  ('o07', 'Dopuri de urechi', 'Opțional', 56),
  ('o08', 'Parazăpezi', 'Opțional', 57),
  ('o09', 'Coardă 10 m, Ø8 mm (1/echipă)', 'Opțional', 58)

on conflict (id) do nothing;

-- migration (v3): travelling on their own
alter table public.profiles add column if not exists own_transport boolean not null default false;

-- migration (v4): locations, 4M team roster, tents
alter table public.config add column if not exists event_name text not null default '' check (char_length(event_name) <= 80);
alter table public.config add column if not exists event_maps text not null default '' check (char_length(event_maps) <= 500);
alter table public.config add column if not exists food_name text not null default '' check (char_length(food_name) <= 80);
alter table public.config add column if not exists food_maps text not null default '' check (char_length(food_maps) <= 500);
create table if not exists public.roster (
  id uuid primary key default gen_random_uuid(),
  team uuid not null references public.teams(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 60),
  profile uuid references public.profiles(id) on delete set null
);
alter table public.roster enable row level security;
drop policy if exists "roster read" on public.roster;
create policy "roster read" on public.roster for select to authenticated using (public.is_approved());
drop policy if exists "roster admin" on public.roster;
create policy "roster admin" on public.roster for all to authenticated using (public.is_admin()) with check (public.is_admin());
create table if not exists public.tents (
  id uuid primary key default gen_random_uuid(),
  team uuid not null references public.teams(id) on delete cascade,
  owner uuid not null references public.profiles(id) on delete cascade,
  places int not null default 2 check (places between 1 and 8),
  label text not null default '' check (char_length(label) <= 40),
  created_at timestamptz not null default now()
);
alter table public.profiles add column if not exists tent uuid references public.tents(id) on delete set null;
alter table public.tents enable row level security;
drop policy if exists "tents read" on public.tents;
create policy "tents read" on public.tents for select to authenticated using (public.is_approved());
drop policy if exists "tents insert own" on public.tents;
create policy "tents insert own" on public.tents for insert to authenticated with check (owner = auth.uid() and public.is_approved());
drop policy if exists "tents change own" on public.tents;
create policy "tents change own" on public.tents for update to authenticated using (owner = auth.uid() or public.is_admin()) with check (owner = auth.uid() or public.is_admin());
drop policy if exists "tents delete own" on public.tents;
create policy "tents delete own" on public.tents for delete to authenticated using (owner = auth.uid() or public.is_admin());
do $$ begin
  begin alter publication supabase_realtime add table public.roster; exception when others then null; end;
  begin alter publication supabase_realtime add table public.tents; exception when others then null; end;
end $$;

-- migration (v5): tent sync with the "Corturi" item, tent placement, downloadable document
alter table public.tents add column if not exists auto boolean not null default false;
alter table public.config add column if not exists doc_url text not null default '' check (char_length(doc_url) <= 500);
alter table public.config add column if not exists doc_name text not null default '' check (char_length(doc_name) <= 80);
-- functions public.sync_tent() (trigger on profiles) and public.tent_place(uuid, uuid, boolean): see Supabase SQL editor history

-- migration (v6): departure details, rider city, location notes, burner/gas split
-- XCC v6 (round-2 review) — additive, safe for the current live app
alter table public.cars add column if not exists meet_point text not null default '' check (char_length(meet_point) <= 60);
alter table public.cars add column if not exists meet_maps text not null default '' check (char_length(meet_maps) <= 500);
alter table public.cars add column if not exists depart_date date;
alter table public.cars add column if not exists depart_time text check (depart_time is null or depart_time ~ '^[0-2][0-9]:[0-5][0-9]');
alter table public.cars add column if not exists back_text text not null default '' check (char_length(back_text) <= 60);
alter table public.profiles add column if not exists city text not null default '' check (char_length(city) <= 40);
alter table public.config add column if not exists event_note text not null default '' check (char_length(event_note) <= 80);
alter table public.config add column if not exists food_note text not null default '' check (char_length(food_note) <= 80);
-- split "Arzător + butelii": e05 keeps the ticks as the burner, gas cans become a new item
update public.items set name = 'Arzător (min. 2/echipă)' where id = 'e05';
insert into public.items (id, name, cat, ord) values ('e06', 'Butelie de gaz (min. 3/echipă)', 'Echipă obligatoriu', 14.5) on conflict (id) do nothing;
select (select count(*) from public.items) as items, (select count(*) from public.cars) as cars;

-- v7: pickup from home
-- XCC v7: pickup from home (additive)
alter table public.profiles add column if not exists pickup boolean not null default false;
alter table public.profiles add column if not exists pickup_maps text not null default '' check (char_length(pickup_maps) <= 500);
alter table public.profiles add column if not exists pickup_note text not null default '' check (char_length(pickup_note) <= 60);
select count(*) as profiles from public.profiles;

-- migration (v8): drivers can take someone out of their car; seats for people on the 4M list without an account
alter table public.roster add column if not exists ride uuid references public.cars(id) on delete set null;

-- the driver (or the organiser) takes a passenger out of the car
create or replace function public.unseat(person uuid) returns void
language plpgsql security definer set search_path = public as $$
declare r uuid;
begin
  select ride into r from public.profiles where id = person;
  if r is null then return; end if;
  if not (public.is_admin() or exists (select 1 from public.cars where id = r and owner = auth.uid())) then
    raise exception 'Doar șoferul mașinii poate scoate pe cineva.';
  end if;
  if exists (select 1 from public.cars where id = r and owner = person) then
    raise exception 'Șoferul nu poate fi scos din mașina lui.';
  end if;
  update public.profiles set ride = null where id = person;
end $$;

-- give / take a seat to someone on the 4M list who has no account (car = null takes them out)
create or replace function public.seat_guest(guest uuid, car uuid) returns void
language plpgsql security definer set search_path = public as $$
declare cur uuid; cap int; drv uuid; used int;
begin
  if not public.is_approved() then raise exception 'Nu ai acces.'; end if;
  select ride into cur from public.roster where id = guest;
  if not found then raise exception 'Persoana nu e pe listă.'; end if;
  if not public.is_admin() then
    if car is null then
      if not exists (select 1 from public.cars where id = cur and owner = auth.uid()) then
        raise exception 'Doar șoferul mașinii sau organizatorul.';
      end if;
    else
      if not exists (select 1 from public.cars where id = car and owner = auth.uid()) then
        raise exception 'Doar în mașina ta.';
      end if;
      if cur is not null and cur <> car and exists (select 1 from public.cars where id = cur) then
        raise exception 'Are deja loc în altă mașină.';
      end if;
    end if;
  end if;
  if car is not null and car is distinct from cur then
    select seats, owner into cap, drv from public.cars where id = car for update;
    if not found then raise exception 'Mașina nu mai există.'; end if;
    select (select count(*) from public.profiles p where p.ride = car and p.id <> drv and p.status = 'approved')
         + (select count(*) from public.roster g where g.ride = car) into used;
    if used >= cap then raise exception 'Mașina e plină.'; end if;
  end if;
  update public.roster set ride = car where id = guest;
end $$;

-- seats given to people without an account count when someone with an account takes a seat
-- (separate trigger, runs after guard_profile; guard_profile itself is left as it is)
create or replace function public.guard_ride_guests() returns trigger
language plpgsql security definer set search_path = public as $$
declare cap int; drv uuid; used int;
begin
  if new.ride is not null and new.ride is distinct from old.ride then
    select seats, owner into cap, drv from public.cars where id = new.ride;
    if drv is distinct from new.id then
      select (select count(*) from public.profiles p where p.ride = new.ride and p.id <> drv and p.id <> new.id and p.status = 'approved')
           + (select count(*) from public.roster g where g.ride = new.ride) into used;
      if used >= cap then raise exception 'Mașina e plină.'; end if;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists guard_ride_guests on public.profiles;
create trigger guard_ride_guests before update on public.profiles
  for each row execute function public.guard_ride_guests();

revoke all on function public.unseat(uuid) from public, anon;
revoke all on function public.seat_guest(uuid, uuid) from public, anon;
grant execute on function public.unseat(uuid) to authenticated;
grant execute on function public.seat_guest(uuid, uuid) to authenticated;
select count(*) as roster from public.roster;
