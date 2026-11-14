-- Synthetic fixture: order table.
CREATE TABLE IF NOT EXISTS demo_orders (
    id BIGINT PRIMARY KEY,
    status VARCHAR(20) NOT NULL,
    amount NUMERIC(12, 2) NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL
);
