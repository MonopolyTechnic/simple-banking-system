# Simple Banking System

A simple banking system template that can be used by banks.

### Setup

1. Install Go v1.22+
2. Install Postgres 17
3. Clone this repo and cd to the directory
4. Log in and connect to psql by running `psql -h localhost -p 5432 -U postgres` in the command line (Note: psql may need to be added to PATH/be set in an environment variable)
5. Enter the password (default password for username postgres is `postgres`).
6. Run `ALTER USER postgres WITH PASSWORD 'new_password';`. Try to avoid special characters.
7. Exit the psql session by typing `\q`.
8. Reconnect to psql with the new password.
9. Run `CREATE DATABASE banking;`
10. Create a `.env` file and fill in values like in `.env.example`

### Run the webserver
1. Run `go run main.go`
2. The server should be up on port 5000!
