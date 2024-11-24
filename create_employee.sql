\prompt 'Enter first name (Admin): ' fname
\prompt 'Enter last name (User): ' lname
\prompt 'Enter email (admin@company.com): ' email
\prompt 'Enter phone number: ' phonenum
\prompt 'Enter phone carrier: ' carrier
\prompt 'Enter password: ' pw

CREATE EXTENSION IF NOT EXISTS pgcrypto;
INSERT INTO profiles(
    profile_type
    ,first_name
    ,last_name,
    email,
    date_of_birth
    ,billing_address
    ,phone_number
    ,phone_carrier
    ,password_hash
    ,masked_password
) VALUES (
    'employee'
    ,COALESCE(NULLIF(:'fname', ''), 'Admin')
    ,COALESCE(NULLIF(:'lname', ''), 'User')
    ,COALESCE(NULLIF(:'email', ''), 'admin@company.com')
    ,CURRENT_DATE
    ,'1600 Amphitheatre Parkway Mountain View, CA 94043'
    ,:'phonenum'
    ,:'carrier'
    ,crypt(:'pw', gen_salt('bf', 10))::BYTEA
    ,CONCAT(SUBSTRING(:'pw' FROM 1 FOR 1), REPEAT('*', LENGTH(:'pw') - 1))
);