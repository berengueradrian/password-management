create database passmanager;

create table users
(
    token         varbinary(256) not null,
    username      varbinary(256) not null,
    password      varbinary(256) not null,
    salt          varbinary(256) not null,
    session_token varbinary(256) null,
    last_seen     varbinary(256) null,
    public_key    varbinary(512) not null,
    private_key   varbinary(2048) not null,
    constraint token
        primary key (token)
);

-- create table public_keys
-- (
--     token      varbinary(256) not null,
--     public_key varbinary(256) not null,
--     constraint token
--         primary key (token),
--     constraint token_fk
--         foreign key (token) references users (token)
-- );

create table credentials
(
    id       int    not null,
    user_id  varbinary(256) not null,
    alias    varbinary(256) not null,
    user     varbinary(256) null,
    password varbinary(256) not null,
    site     varbinary(256) null,
    constraint id
        primary key (id),
    constraint user_id
        foreign key (user_id) references users (token)
);

create table files
(
    id            int    not null,
    credential_id int    not null,
    path          varbinary(256) not null,
    constraint id
        primary key (id),
    constraint credential_id
        foreign key (credential_id) references credentials (id)
);
