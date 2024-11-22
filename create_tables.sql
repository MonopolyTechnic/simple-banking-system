CREATE TABLE IF NOT EXISTS profiles(
    id                  INT
                        NOT NULL
                        PRIMARY KEY
                        GENERATED ALWAYS AS IDENTITY  -- Starts at 1 and increases by 1 for each new row
                        CHECK (id > 0)  -- Check to make sure the id > 0 on every insert/update
    ,profile_type       CHAR(8)
                        NOT NULL
                        CHECK (profile_type IN ('employee', 'customer'))
    ,first_name         VARCHAR(64)
                        NOT NULL
    ,middle_name        VARCHAR(64)
    ,last_name          VARCHAR(64)
                        NOT NULL
    ,email              VARCHAR(128)
                        NOT NULL
                        UNIQUE
    ,date_of_birth      DATE
                        NOT NULL
    ,billing_address    VARCHAR(256)
                        NOT NULL
    ,phone_number       VARCHAR(10)
                        NOT NULL
                        UNIQUE
    ,phone_carrier      VARCHAR(32)
                        NOT NULL
    ,password_hash      BYTEA
                        NOT NULL
    ,masked_password    VARCHAR(32)
                        NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts(
    account_num             CHAR(16)
                            NOT NULL
                            PRIMARY KEY
    ,primary_customer_id    INT
                            NOT NULL
                            CHECK (
                                secondary_customer_id IS NULL OR
                                primary_customer_id <> secondary_customer_id
                            )
    ,secondary_customer_id  INT
                            CHECK (
                                secondary_customer_id IS NULL OR
                                primary_customer_id <> secondary_customer_id
                            )
    ,account_type           VARCHAR(8)
                            NOT NULL
                            CHECK (account_type IN ('checking', 'savings'))
    ,balance                NUMERIC(15, 2)  -- 15 digits, with 2 of those being after the decimal
                            NOT NULL
                            CHECK (balance >= 0)
    ,FOREIGN KEY (primary_customer_id)
        REFERENCES profiles(id)
    ,FOREIGN KEY (secondary_customer_id)
        REFERENCES profiles(id)
);
CREATE TABLE IF NOT EXISTS transactions(
    transaction_id          BIGINT
                            NOT NULL
                            PRIMARY KEY
                            GENERATED ALWAYS AS IDENTITY  -- Starts at 1 and increases by 1 for each new row
                            CHECK (transaction_id > 0)
    ,source_account         CHAR(16)
    ,recipient_account      CHAR(16)
    ,amount                 NUMERIC(15, 2)  -- 15 digits, with 2 of those being after the decimal
                            NOT NULL
                            CHECK (amount >= 0)
    ,transaction_type       VARCHAR(8)
                            CHECK (transaction_type IN ('deposit', 'withdraw'))
    ,transaction_timestamp  TIMESTAMP
                            NOT NULL
    ,FOREIGN KEY (source_account)
        REFERENCES accounts(account_num)
    ,FOREIGN KEY (recipient_account)
        REFERENCES accounts(account_num)
);