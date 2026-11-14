-- qianshen: long-transaction
ALTER TABLE demo_events
    ADD COLUMN IF NOT EXISTS region VARCHAR(8) NOT NULL DEFAULT 'unknown';
