-- Synthetic fixture: parent/child tables with an inline foreign key.
CREATE TABLE IF NOT EXISTS demo_invoice_parent (
    id BIGINT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS demo_invoice_child (
    id BIGINT PRIMARY KEY,
    parent_id BIGINT REFERENCES demo_invoice_parent(id)
);
