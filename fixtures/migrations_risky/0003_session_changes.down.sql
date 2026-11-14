DROP INDEX IF EXISTS idx_demo_sessions_state;
DELETE FROM demo_sessions WHERE id < 0;
