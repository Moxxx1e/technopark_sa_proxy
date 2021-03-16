\c postgres;

create database proxy_db;

\c proxy_db;

CREATE TABLE IF NOT EXISTS requests
(
    id      serial primary key,
    host    text NOT NULL,
    request text NOT NULL,
    tls     smallint NOT NULL
);