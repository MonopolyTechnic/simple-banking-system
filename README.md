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
10. Create a `.env` file and fill in values by following the example in `.env.example`

### Run the webserver
1. Run `go run .`
2. The server should be up on the port specified in `.env`

### Adding an Employee
These steps should be done after running the webserver at least once.
1. Connect to the database using `psql -h localhost -p 5432 -U postgres -d banking`. Make sure you run this in the base directory of the project.
2. Run `\i create_employee.sql`. Enter all the values when prompted. A value in parenthesis indicates the default value if left empty.

### Website Customization
To customize the look of the website, modify the values in the `config.env` file.
- `BANK_NAME` should be replaced with the name of the bank.
- `LOGO` should include the url of or file path to the bank's logo.
- `BANNER` should include the url of or file path to the image to be used for the top banner.
- `PRIMARY_HEX` should include the hex code for the primary color of the website. Note: include the `#` (e.g. `#545F71`)
