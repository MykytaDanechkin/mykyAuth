--liquibase formatted sql

--changeset mykyda:1
create table users
(
    id       bigserial primary key,
    email    text unique not null,
    password text        not null,
    authority     text default 'USER' check ( authority in ('USER', 'ADMIN') )
);