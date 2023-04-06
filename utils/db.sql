create database passmanager;

create table users
(
    token         binary not null,
    username      binary not null,
    password      binary not null,
    salt          binary not null,
    session_token binary null,
    last_seen     binary null,
    constraint token
        primary key (token)
);

create table public_keys
(
    token      binary not null,
    public_key binary not null,
    constraint token
        primary key (token),
    constraint token_fk
        foreign key (token) references users (token)
);

create table credentials
(
    id       int    not null,
    user_id  binary not null,
    alias    binary not null,
    user     binary null,
    password binary not null,
    site     binary null,
    constraint id
        primary key (id),
    constraint user_id
        foreign key (user_id) references users (token)
);

create table files
(
    id            int    not null,
    credential_id int    not null,
    path          binary not null,
    constraint id
        primary key (id),
    constraint credential_id
        foreign key (credential_id) references credentials (id)
);
