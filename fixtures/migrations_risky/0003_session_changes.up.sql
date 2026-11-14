BEGIN;
CREATE INDEX IF NOT EXISTS idx_demo_sessions_state ON demo_sessions (state);
INSERT INTO demo_sessions (id, state) VALUES (1, 'open');
UPDATE demo_sessions SET state = 'closed';
DELETE FROM demo_sessions;
GRANT SELECT ON demo_sessions TO demo_reader;
COMMIT;
