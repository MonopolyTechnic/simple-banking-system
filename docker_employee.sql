CREATE EXTENSION IF NOT EXISTS pgcrypto;
INSERT INTO profiles(
    profile_type, first_name, last_name, email, date_of_birth, billing_address, phone_number, phone_carrier, password_hash, masked_password
) VALUES (
    'employee',
    'Admin', 'User',
    'admin@company.com',
    CURRENT_DATE,
    '1600 Amphitheatre Parkway Mountain View, CA 94043',
    '3333333333',
    'AT&T',
    crypt('mypassword', gen_salt('bf', 10))::BYTEA,
    '******'
);
