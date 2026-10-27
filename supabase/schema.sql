-- Sala Giochi · schema Supabase. Incolla tutto nel SQL Editor ed esegui (una volta).
create extension if not exists pgcrypto;

create table sessions(
 id uuid primary key default gen_random_uuid(),
 code text not null unique check (code ~ '^[0-9]{4}$'),
 mode text not null default 'single' check (mode in ('single','duel','group')),
 status text not null default 'lobby' check (status in ('lobby','playing','ended')),
 round int not null default 0,
 sel text not null default 'reflex',
 game text,
 duel jsonb not null default '[]',
 created_at timestamptz not null default now(),
 ended_at timestamptz);
create table players(
 id uuid primary key default gen_random_uuid(),
 session_id uuid not null references sessions on delete cascade,
 name text not null check (char_length(name) between 1 and 20),
 allowed boolean not null default false,
 diff text not null default 'normale' check (diff in ('lento','normale','veloce')),
 bot boolean not null default false,
 created_at timestamptz not null default now());
create table player_secrets(player_id uuid primary key references players on delete cascade, secret uuid not null default gen_random_uuid());
create table presence(player_id uuid primary key references players on delete cascade, seen timestamptz not null default now());
create table rounds(session_id uuid references sessions on delete cascade, round int, game text not null, name text not null, mode text not null, primary key(session_id,round));
create table scores(player_id uuid references players on delete cascade, round int, session_id uuid not null references sessions on delete cascade, pts int not null check (pts between 0 and 5000), det text not null default '', primary key(player_id,round));
create index on players(session_id);
create index on scores(session_id);

-- Sicurezza (RLS): i partecipanti (anonimi) leggono solo la sessione attiva, o conclusa da meno di 15 minuti.
-- L'archivio e le scritture sono riservati all'animatore (utente Supabase Auth).
create function visible(sid uuid) returns boolean language sql stable security definer set search_path=public as $$
 select auth.uid() is not null or exists(select 1 from sessions where id=sid and (status<>'ended' or ended_at>now()-interval '15 minutes')) $$;
create function _auth(p_id uuid,p_secret uuid) returns boolean language sql stable security definer set search_path=public as $$
 select exists(select 1 from player_secrets where player_id=p_id and secret=p_secret) $$;
revoke execute on function _auth(uuid,uuid) from public, anon, authenticated;

alter table sessions enable row level security;
alter table players enable row level security;
alter table scores enable row level security;
alter table rounds enable row level security;
alter table presence enable row level security;
alter table player_secrets enable row level security;  -- nessuna policy: inaccessibile dall'esterno

create policy r_sessions on sessions for select using (visible(id));
create policy r_players on players for select using (visible(session_id));
create policy r_scores on scores for select using (visible(session_id));
create policy r_rounds on rounds for select using (visible(session_id));
create policy w_sessions on sessions for all to authenticated using (true) with check (true);
create policy w_players on players for all to authenticated using (true) with check (true);
create policy w_scores on scores for all to authenticated using (true) with check (true);
create policy w_rounds on rounds for all to authenticated using (true) with check (true);
create policy w_presence on presence for all to authenticated using (true) with check (true);

-- Azioni dei partecipanti: solo tramite queste funzioni, con un segreto personale.
create function join_session(p_code text,p_name text) returns json language plpgsql security definer set search_path=public as $$
declare s sessions; pid uuid; sec uuid;
begin
 select * into s from sessions where code=p_code and status<>'ended';
 if not found then raise exception 'codice non valido'; end if;
 if (select count(*) from players where session_id=s.id)>=60 then raise exception 'stanza piena'; end if;
 insert into players(session_id,name) values(s.id,left(trim(p_name),20)) returning id into pid;
 insert into player_secrets(player_id) values(pid) returning secret into sec;
 return json_build_object('id',pid,'sid',s.id,'secret',sec);
end $$;
create function submit_score(p_id uuid,p_secret uuid,p_round int,p_pts int,p_det text) returns void language plpgsql security definer set search_path=public as $$
declare s sessions; p players;
begin
 if not _auth(p_id,p_secret) then raise exception 'non autorizzato'; end if;
 select * into p from players where id=p_id;
 select * into s from sessions where id=p.session_id;
 if s.status<>'playing' or s.round<>p_round or not p.allowed then raise exception 'gioco non attivo'; end if;
 if s.mode='duel' and not (s.duel @> to_jsonb(p_id::text)) then raise exception 'non sei uno sfidante'; end if;
 insert into scores(player_id,round,session_id,pts,det) values(p_id,p_round,s.id,least(greatest(p_pts,0),5000),left(coalesce(p_det,''),60)) on conflict do nothing;
end $$;
create function heartbeat(p_id uuid,p_secret uuid) returns void language plpgsql security definer set search_path=public as $$
begin if _auth(p_id,p_secret) then insert into presence(player_id) values(p_id) on conflict(player_id) do update set seen=now(); end if; end $$;
create function leave_session(p_id uuid,p_secret uuid) returns void language plpgsql security definer set search_path=public as $$
begin if _auth(p_id,p_secret) then delete from players where id=p_id; end if; end $$;

-- Realtime
alter publication supabase_realtime add table sessions, players, scores, rounds;

-- Cancellazione automatica dopo 30 giorni (promessa nella pagina Privacy).
create function purge_old() returns void language sql security definer set search_path=public as $$
 delete from sessions where created_at < now()-interval '30 days' $$;
revoke execute on function purge_old() from public, anon, authenticated;
-- Attiva prima l'estensione pg_cron (Dashboard > Database > Extensions), poi togli il commento:
-- select cron.schedule('purge-sala-giochi','0 3 * * *','select public.purge_old()');
