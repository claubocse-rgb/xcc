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
