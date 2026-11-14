-- dialect: postgres (synthetic fixture)
CREATE TABLE IF NOT EXISTS demo_dialect_pg (
    id INTEGER PRIMARY KEY,
    label TEXT NOT NULL DEFAULT 'demo'
);
