-- Synthetic fixture: baseline account table.
CREATE TABLE IF NOT EXISTS demo_accounts (
    id BIGINT PRIMARY KEY,
    email VARCHAR(120) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
