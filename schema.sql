-- HomeworkAI v2 database
-- Run the entire file in Supabase SQL Editor.

create extension if not exists pgcrypto;
create extension if not exists vector;

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  username text not null unique,
  telegram_username text not null unique,
  telegram_chat_id bigint,
  password_hash text not null,
  role text not null default 'user' check (role in ('user','manager','admin')),
  status text not null default 'pending' check (status in ('pending','approved','blocked')),
  plan text not null default 'Standard' check (plan in ('Standard','Start','Plus','Pro')),
  plan_expires_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_users_username on users(username);
create index if not exists idx_users_telegram on users(telegram_username);
create index if not exists idx_users_status on users(status);
create index if not exists idx_users_plan on users(plan,plan_expires_at);

create table if not exists telegram_links (
  username text primary key,
  chat_id bigint not null,
  verified boolean not null default true,
  updated_at timestamptz not null default now()
);
create index if not exists idx_telegram_links_chat on telegram_links(chat_id);

create table if not exists telegram_verifications (
  id uuid primary key default gen_random_uuid(),
  telegram_username text not null,
  telegram_chat_id bigint not null,
  code_hash text not null,
  expires_at timestamptz not null,
  used boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists idx_tg_verify on telegram_verifications(telegram_username,expires_at desc);

create table if not exists homework (
  id uuid primary key default gen_random_uuid(),
  subject text not null unique,
  title text not null default '',
  body text not null default '',
  due_text text not null default '',
  updated_by uuid references users(id) on delete set null,
  updated_at timestamptz not null default now()
);
create index if not exists idx_homework_subject on homework(subject);

create table if not exists announcements (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  body text not null,
  expires_at timestamptz not null,
  created_by uuid references users(id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists idx_announcements_expiry on announcements(expires_at);

create table if not exists textbook_chunks (
  id uuid primary key default gen_random_uuid(),
  subject text not null,
  book_title text not null,
  chapter text not null default '',
  content text not null,
  embedding vector(1536),
  created_at timestamptz not null default now()
);
create index if not exists idx_textbook_subject on textbook_chunks(subject);
create index if not exists idx_textbook_embedding on textbook_chunks using hnsw (embedding vector_cosine_ops);

create or replace function match_textbook_chunks(
  query_embedding vector(1536),
  match_threshold float,
  match_count int,
  filter_subject text
)
returns table(
  id uuid,
  subject text,
  book_title text,
  chapter text,
  content text,
  similarity float
)
language sql stable
as $$
  select id,subject,book_title,chapter,content,
         1 - (embedding <=> query_embedding) as similarity
  from textbook_chunks
  where embedding is not null
    and subject = filter_subject
    and 1 - (embedding <=> query_embedding) >= match_threshold
  order by embedding <=> query_embedding
  limit match_count;
$$;

create table if not exists ai_solutions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  homework_id uuid references homework(id) on delete set null,
  subject text not null,
  question text not null,
  solution text not null,
  model text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '24 hours')
);
create index if not exists idx_ai_solutions_expiry on ai_solutions(user_id,expires_at desc);

create table if not exists ai_chat_messages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  subject text not null,
  model text not null,
  role text not null check (role in ('user','assistant')),
  content text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '24 hours')
);
create index if not exists idx_ai_chat_expiry on ai_chat_messages(user_id,expires_at desc);
create index if not exists idx_ai_chat_quota on ai_chat_messages(user_id,role,created_at desc);

create table if not exists support_chats (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  ai_enabled boolean not null default true,
  human_requested boolean not null default false,
  status text not null default 'open' check (status in ('open','closed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index if not exists ux_support_open_user on support_chats(user_id) where status='open';
create index if not exists idx_support_updated on support_chats(updated_at desc);

create table if not exists support_messages (
  id uuid primary key default gen_random_uuid(),
  chat_id uuid not null references support_chats(id) on delete cascade,
  sender_type text not null check (sender_type in ('user','ai','human','system')),
  content text not null,
  created_at timestamptz not null default now()
);
create index if not exists idx_support_messages on support_messages(chat_id,created_at);

create table if not exists deletion_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now()
);
create unique index if not exists ux_pending_deletion on deletion_requests(user_id) where status='pending';

create table if not exists registration_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now()
);
create unique index if not exists ux_pending_registration on registration_requests(user_id) where status='pending';

create table if not exists plan_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  requested_plan text not null check (requested_plan in ('Start','Plus','Pro')),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now()
);
create unique index if not exists ux_pending_plan on plan_requests(user_id) where status='pending';

create table if not exists service_settings (
  id boolean primary key default true,
  stopped boolean not null default false,
  message text not null default '',
  updated_at timestamptz not null default now()
);
insert into service_settings(id,stopped,message) values(true,false,'') on conflict(id) do nothing;

create table if not exists faq (
  id boolean primary key default true,
  content text not null default ''
);
insert into faq(id,content) values(true,'') on conflict(id) do nothing;

insert into homework(subject) values
('Алгебра'),('Геометрия'),('Физика'),('Русская литература/язык'),('Белорусская литература/язык'),
('Информатика'),('История Всемирная/Беларуси'),('Биология'),('География'),('Английский'),('Химия')
on conflict(subject) do nothing;

-- Optional basic cleanup helpers.
create or replace function cleanup_homeworkai_expired()
returns void
language plpgsql
as $$
begin
  delete from announcements where expires_at < now();
  delete from ai_solutions where expires_at < now();
  delete from ai_chat_messages where expires_at < now();
  delete from telegram_verifications where expires_at < now() or used = true;
  delete from support_messages where created_at < now() - interval '24 hours';
end;
$$;
