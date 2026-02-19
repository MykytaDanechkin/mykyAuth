--liquibase formatted sql

--changeset mykyda:2
create table refresh_token
(
    id         uuid primary key,
    user_id    bigint references users (id) on delete cascade,
    token_hash text not null,
    created_at date not null,
    expires_at date not null,
    is_revoked boolean default true
);