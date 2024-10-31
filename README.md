# Simple Banking System

A simple banking system template that can be used by banks.

### Setup

1. Install Go v1.22+
2. Install Postgres 17
3. Clone this repo and cd to the directory
4. [Log into and connect to psql](https://stackoverflow.com/a/50299351) (default password for user `postgres` is `postgres`)
5. Run `ALTER USER postgres WITH PASSWORD 'new_password';`. Try to avoid special characters.
6. Close and reconnect to psql with the new password.
7. Run `CREATE DATABASE banking;`
8. Create a `.env` file and fill in values like in `.env.example`

### Run the webserver
1. Run `go run main.go`
2. The server should be up on port 5000!
