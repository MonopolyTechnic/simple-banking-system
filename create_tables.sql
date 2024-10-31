CREATE TABLE IF NOT EXISTS employees(
    id                  INT
                        NOT NULL
                        PRIMARY KEY
                        GENERATED ALWAYS AS IDENTITY  -- Starts at 1 and increases by 1 for each new row
                        CHECK (id > 0)  -- Check to make sure the id > 0 on every insert/update
    ,first_name         VARCHAR(64)
                        NOT NULL
    ,middle_name        VARCHAR(64)
    ,last_name          VARCHAR(64)
                        NOT NULL
    ,email              VARCHAR(128)
                        NOT NULL
    ,date_of_birth      DATE
                        NOT NULL
    ,billing_address    VARCHAR(256)
                        NOT NULL
    ,phone_number       VARCHAR(10)
                        NOT NULL
    ,phone_carrier      VARCHAR(16)
                        NOT NULL
    ,password_hash      BYTEA
                        NOT NULL
);