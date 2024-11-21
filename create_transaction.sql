CREATE EXTENSION IF NOT EXISTS pgcrypto;

INSERT INTO transactions(
    source_account,
    recipient_account,
    amount,
    transaction_type,
    transaction_timestamp
) 
VALUES (
    '0000000000000002',
    '0000000000000001',
    250,
    'deposit',
    CURRENT_TIMESTAMP
);
