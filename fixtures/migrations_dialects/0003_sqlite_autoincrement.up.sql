-- dialect: sqlite (synthetic fixture)
CREATE TABLE IF NOT EXISTS demo_dialect_sq (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL
);
INSERT OR REPLACE INTO demo_dialect_sq (id, label) VALUES (1, 'demo');
