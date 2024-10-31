CREATE TABLE IF NOT EXISTS employees(
    id              INT
                    NOT NULL
                    PRIMARY KEY
                    GENERATED ALWAYS AS IDENTITY  -- Starts at 1 and increases by 1 for each new row
                    CHECK (id > 0)  -- Check to make sure the id > 0 on every insert/update
    ,firstname      VARCHAR(64)
                    NOT NULL
    ,middlename     VARCHAR(64)
    ,lastname       VARCHAR(64)
                    NOT NULL
    ,email          VARCHAR(128)
                    NOT NULL
    ,dob            DATE
                    NOT NULL
    ,billingaddress VARCHAR(256)
                    NOT NULL
    ,phonenum       VARCHAR(10)
                    NOT NULL
    ,passwordhash   BYTEA
                    NOT NULL
);