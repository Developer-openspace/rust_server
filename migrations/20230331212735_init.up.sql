-- Add up migration script here
create table users(
    username varchar not null,
    email varchar not null unique,
    password varchar not null
);
create unique index user_index on users (email);
