create database passmanager;
use passmanager;
-- users table where the login in the password management app is stored
create table users
(
    username      varbinary(256) not null,
    password      varbinary(256) not null,
    salt          varbinary(256) not null,
    session_token varbinary(256) null,
    last_seen     varbinary(256) null,
    public_key    varbinary(512) not null,
    private_key   varbinary(2048) not null,
    constraint username
        primary key (username)
);

-- users_data table stored cyphered with the user's keyData (uknown on the server)
-- it will store the credentials data except the password for the user to be able
-- it will also store the AES key that encrypted the credentials data so that only the user is able to decrypt it
-- to search on the app without the server directly associating the user and its credentials
create table users_data
(
    id       varbinary(256) not null,
    site  varbinary(256) not null,
    username varbinary(256) null,
    aes_key  varbinary(256) not null,
    user_id  varbinary(256) not null,
    alias varbinary(256) null,
    constraint id
        primary key (id),
    constraint user_id
        foreign key (user_id) references users (username)
            on delete cascade
);

-- credentials table stored encrypted (disk encryption, db encryption...)
-- and with the user's data also encrypted with the user's keyData
-- it will store all the credentials data included the password
create table credentials
(
    users_data_id varbinary(256) not null,
    password varbinary(256) not null,
    constraint users_data_id
        primary key (users_data_id),
    constraint users_data_id
        foreign key (users_data_id) references users_data (id) on update cascade
);

-- files table where the files associated to the credentials are stored
-- stored encrypted (disk encryption, db encryption...)
create table files
(
    id            int    not null,
    credential_id varbinary(256)    not null,
    path          varbinary(256) not null,
    constraint id
        primary key (id),
    constraint credential_id
        foreign key (credential_id) references credentials (users_data_id)
);
