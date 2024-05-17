CREATE DATABASE telegram_bot;
CREATE USER repl_user WITH REPLICATION ENCRYPTED PASSWORD 'Qq12345';
\c telegram_bot;
CREATE TABLE emails(
    id SERIAL PRIMARY KEY, 
    email VARCHAR(255)
);

CREATE TABLE phone_numbers(
    id SERIAL PRIMARY KEY,
    phone_number VARCHAR(20)
);

